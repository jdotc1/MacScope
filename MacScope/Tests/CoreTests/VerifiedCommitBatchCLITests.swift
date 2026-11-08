#if DEBUG
import Foundation
import XCTest
@testable import MacScope

/// Request decoding for the DEBUG-only VA-G writer harness. No store, binary or package is opened.
final class VerifiedCommitBatchCLITests: XCTestCase {
    @MainActor
    func testDecodesPlanAndCommitRequests() throws {
        let plan = try VerifiedCommitBatchCLI.Request.decode(Data(
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","include":["0x100157ebc"],"functionCount":10}"#.utf8))
        XCTAssertEqual(plan.action, .plan)
        XCTAssertEqual(plan.include, [0x100157ebc])
        XCTAssertEqual(plan.functionCount, 10)
        XCTAssertNil(plan.plan)
        XCTAssertFalse(plan.injectReadbackMismatch)

        let commit = try VerifiedCommitBatchCLI.Request.decode(Data(
            #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out","plan":"/tmp/f.json","injectReadbackMismatch":true}"#.utf8))
        XCTAssertEqual(commit.action, .commit)
        XCTAssertEqual(commit.plan?.path, "/tmp/f.json")
        XCTAssertTrue(commit.injectReadbackMismatch)
        XCTAssertEqual(commit.functionCount, 10)
        XCTAssertTrue(commit.include.isEmpty)
    }

    @MainActor
    func testDeadlineOverrideIsBoundedAndOptional() throws {
        let base = #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out","plan":"/tmp/f.json""#
        XCTAssertEqual(try VerifiedCommitBatchCLI.Request.decode(Data((base + "}").utf8)).deadlineSeconds, 590)
        XCTAssertEqual(try VerifiedCommitBatchCLI.Request.decode(Data((base + #","deadlineSeconds":3540}"#).utf8)).deadlineSeconds, 3540)
        for bad in ["59", "3601", "\"600\"", "-1"] {
            XCTAssertThrowsError(try VerifiedCommitBatchCLI.Request.decode(Data((base + #","deadlineSeconds":"# + bad + "}").utf8)), bad)
        }
    }

    /// The deadline timer helper fires, on time, with no app launch. The production handler only adds the
    /// `write(2)` and `_exit` of `ProcessDeadline.writeAndExit`, which cannot run inside a test process.
    func testProcessDeadlineTimerFiresOnTime() {
        let fired = expectation(description: "deadline fired")
        let start = ContinuousClock.now
        let elapsed = ElapsedBox()
        let deadline = VerifiedCommitBatchCLI.ProcessDeadline(seconds: 0.3) {
            elapsed.set(ContinuousClock.now - start)
            fired.fulfill()
        }
        wait(for: [fired], timeout: 10)
        withExtendedLifetime(deadline) {}
        let seconds = Double(elapsed.value.components.seconds) + Double(elapsed.value.components.attoseconds) / 1e18
        XCTAssertGreaterThanOrEqual(seconds, 0.29)
        XCTAssertLessThan(seconds, 5, "a strict zero-leeway timer is not coalesced")
    }

    func testProcessDeadlineDoesNotFireOnceReleased() {
        let notFired = expectation(description: "released deadline must not fire")
        notFired.isInverted = true
        var deadline: VerifiedCommitBatchCLI.ProcessDeadline? = VerifiedCommitBatchCLI.ProcessDeadline(seconds: 0.2) {
            notFired.fulfill()
        }
        deadline = nil
        wait(for: [notFired], timeout: 0.8)
        XCTAssertNil(deadline)
    }

    private final class ElapsedBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Duration = .zero
        func set(_ value: Duration) { lock.withLock { stored = value } }
        var value: Duration { lock.withLock { stored } }
    }

    @MainActor
    func testRejectsMalformedAndAmbiguousRequests() {
        let invalid = [
            #"{"action":"plan","binary":"app","output":"/tmp/out"}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"out"}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","unknown":1}"#,
            #"{"action":"scan","binary":"/tmp/app","output":"/tmp/out"}"#,
            #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out"}"#,
            #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out","plan":"rel.json"}"#,
            #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out","plan":"/tmp/f.json","include":["0x1"]}"#,
            #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out","plan":"/tmp/f.json","functionCount":3}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","plan":"/tmp/f.json"}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","injectReadbackMismatch":true}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","functionCount":0}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","functionCount":65}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","include":["100157ebc"]}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/out","include":["0xzz"]}"#,
            #"{"action":"commit","binary":"/tmp/app","output":"/tmp/out","plan":"/tmp/f.json","injectReadbackMismatch":"yes"}"#,
            #"{"action":"plan","binary":"/tmp/app","output":"/tmp/app/inside"}"#,
            #"{"action":"plan","action":"commit","binary":"/tmp/app","output":"/tmp/out"}"#
        ]
        for json in invalid {
            XCTAssertThrowsError(try VerifiedCommitBatchCLI.Request.decode(Data(json.utf8)), json)
        }
    }

    @MainActor
    func testReservedFlagIsOnlyRecognisedAsFirstArgument() {
        XCTAssertNil(VerifiedCommitBatchCLI.requestPath(from: ["MacScope"]))
        XCTAssertNil(VerifiedCommitBatchCLI.requestPath(from: ["MacScope", "--other", "/tmp/r.json"]))
        XCTAssertEqual(
            VerifiedCommitBatchCLI.requestPath(from: ["MacScope", VerifiedCommitBatchCLI.flag, "/tmp/r.json"]),
            "/tmp/r.json")
    }
}
#endif
