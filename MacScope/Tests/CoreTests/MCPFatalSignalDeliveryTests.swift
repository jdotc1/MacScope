// Authored, unrun.
import Darwin
import Foundation
import MacScopeChildProcessC
import MacScopeFatalSignalC
import XCTest
@testable import MacScope

private enum DeliveryStep {
    case bytes(Int)
    case failure(Int32)
    case zero
}

private struct DeliveryScript {
    var steps: [DeliveryStep] = []
    var fallback: DeliveryStep = .bytes(Int.max)
    var attempts = 0
    var delivered: [UInt8] = []
    var descriptors: [Int32] = []
}

// Only this @MainActor test class uses the synchronous callback and its script.
nonisolated(unsafe) private var deliveryScript = DeliveryScript()

private let deliveryWriter: @convention(c) (Int32, UnsafeRawPointer?, Int) -> Int = { fd, buffer, count in
    let index = deliveryScript.attempts
    deliveryScript.attempts += 1
    deliveryScript.descriptors.append(fd)
    let step = index < deliveryScript.steps.count ? deliveryScript.steps[index] : deliveryScript.fallback
    switch step {
    case .bytes(let maximum):
        let written = min(maximum, count)
        guard let buffer else { errno = EBADF; return -1 }
        deliveryScript.delivered.append(contentsOf:
            UnsafeBufferPointer(start: buffer.assumingMemoryBound(to: UInt8.self), count: written))
        return written
    case .failure(let code):
        errno = code
        return -1
    case .zero:
        return 0
    }
}

@MainActor
final class MCPFatalSignalDeliveryTests: XCTestCase {
    private func report() -> [CChar] {
        var storage = [CChar](repeating: 0, count: 256)
        let count = storage.withUnsafeMutableBufferPointer {
            MCPFatalSignalReporter.formatReport(signal: SIGSEGV, slot: MCPLaunchState.ready.slot,
                                                into: $0.baseAddress!, capacity: $0.count)
        }
        return Array(storage.prefix(count))
    }

    private func write(_ bytes: [CChar], steps: [DeliveryStep] = [],
                       fallback: DeliveryStep = .bytes(Int.max), cap: UInt32) -> Int {
        deliveryScript = DeliveryScript(steps: steps, fallback: fallback)
        return bytes.withUnsafeBufferPointer {
            Int(MacScopeFatalWriteAll(123, $0.baseAddress, $0.count, deliveryWriter, cap))
        }
    }

    func testReporterShortWriteCompletesBoundedLine() {
        let originalErrno = errno
        defer { errno = originalErrno; deliveryScript = DeliveryScript() }
        let bytes = report()
        let expected = Array("MacScope MCP: terminated by signal SIGSEGV (\(SIGSEGV)) in state ready\n".utf8)
        XCTAssertEqual(bytes.map { UInt8(bitPattern: $0) }, expected)
        let cap = UInt32(MacScopeFatalWriteAttemptLimit)
        XCTAssertEqual(write(bytes, fallback: .bytes(1), cap: cap), bytes.count)
        XCTAssertEqual(deliveryScript.delivered, expected)
        XCTAssertEqual(deliveryScript.attempts, bytes.count)
        XCTAssertLessThanOrEqual(deliveryScript.attempts, Int(cap))
        XCTAssertEqual(deliveryScript.descriptors, Array(repeating: 123, count: bytes.count))
    }

    func testReporterEINTRRetriesWithinCap() {
        let originalErrno = errno
        defer { errno = originalErrno; deliveryScript = DeliveryScript() }
        let bytes = report()
        let expected = bytes.map { UInt8(bitPattern: $0) }
        XCTAssertEqual(write(bytes, steps: Array(repeating: .failure(EINTR), count: 3), cap: 4), bytes.count)
        XCTAssertEqual(deliveryScript.attempts, 4)
        XCTAssertEqual(deliveryScript.delivered, expected)
        XCTAssertEqual(write(bytes, fallback: .failure(EINTR), cap: 7), 0)
        XCTAssertEqual(deliveryScript.attempts, 7)
        XCTAssertEqual(deliveryScript.delivered, [])
        XCTAssertLessThan(deliveryScript.delivered.count, bytes.count)
        XCTAssertEqual(write(bytes, steps: [.bytes(3)], fallback: .failure(EINTR), cap: 4), 3)
        XCTAssertEqual(deliveryScript.attempts, 4)
        XCTAssertEqual(deliveryScript.delivered, Array(expected.prefix(3)))
    }

    func testReporterZeroOrErrorStops() {
        let originalErrno = errno
        defer { errno = originalErrno; deliveryScript = DeliveryScript() }
        let bytes = report()
        for step in [DeliveryStep.zero, .failure(EBADF), .failure(EPIPE)] {
            // Stale EINTR must not make a zero return retry.
            errno = EINTR
            XCTAssertEqual(write(bytes, steps: [step], cap: 8), 0)
            XCTAssertEqual(deliveryScript.attempts, 1)
            XCTAssertEqual(deliveryScript.delivered, [])
        }
        XCTAssertEqual(write(bytes, steps: [.bytes(2), .failure(EPIPE)], cap: 8), 2)
        XCTAssertEqual(deliveryScript.attempts, 2)
        XCTAssertEqual(deliveryScript.delivered, Array(bytes.prefix(2)).map { UInt8(bitPattern: $0) })
        XCTAssertEqual(write(bytes, cap: 0), 0)
        XCTAssertEqual(deliveryScript.attempts, 0)
        XCTAssertEqual(write([], cap: 8), 0)
        XCTAssertEqual(deliveryScript.attempts, 0)
    }

    func testReporterEAGAINIsBounded() {
        let originalErrno = errno
        defer { errno = originalErrno; deliveryScript = DeliveryScript() }
        let bytes = report()
        XCTAssertEqual(write(bytes, fallback: .failure(EAGAIN), cap: 9), 0)
        XCTAssertEqual(deliveryScript.attempts, 9)
        XCTAssertEqual(deliveryScript.delivered, [])
        XCTAssertEqual(write(bytes, steps: [.failure(EAGAIN), .bytes(2), .failure(EINTR)], cap: 4), bytes.count)
        XCTAssertEqual(deliveryScript.attempts, 4)
        XCTAssertEqual(deliveryScript.delivered, bytes.map { UInt8(bitPattern: $0) })
    }

    func testStackSetupFailureIsReportedBeforeAdmission() {
        var events: [String] = []
        let failed = MCPFatalSignalReporter.installForLaunch(
            signals: [SIGUSR2], log: { events.append($0) },
            installStep: { signals in
                events.append("install")
                XCTAssertEqual(signals, [SIGUSR2])
                return [SIGUSR2: sigaction()]
            },
            stackStep: { events.append("stack"); return -1 })
        events.append("admit") // A marker only; no server, request or process is started.
        XCTAssertEqual(failed.unavailableSignals, [])
        XCTAssertEqual(failed.stackStatus, -1)
        XCTAssertEqual(events, ["install", "stack", "fatal reporter incomplete: alternate stack unavailable", "admit"])

        events = []
        let success = MCPFatalSignalReporter.installForLaunch(
            signals: [SIGUSR2], log: { events.append($0) },
            installStep: { _ in [SIGUSR2: sigaction()] }, stackStep: { 0 })
        XCTAssertEqual(success.unavailableSignals, [])
        XCTAssertEqual(success.stackStatus, 0)
        XCTAssertEqual(events, [])

        let both = MCPFatalSignalReporter.installForLaunch(
            signals: [SIGUSR2], log: { events.append($0) },
            installStep: { _ in [:] }, stackStep: { -1 })
        XCTAssertEqual(both.unavailableSignals, [SIGUSR2])
        XCTAssertEqual(both.stackStatus, -1)
        XCTAssertEqual(events, ["fatal reporter incomplete: handlers unavailable [SIGUSR2]; alternate stack unavailable"])
    }

    func testInstallSkipIsObservable() throws {
        var initial = sigaction()
        try XCTUnwrap(MacScopeReadSignalDisposition(SIGUSR2, &initial) == 0 ? true : nil)
        var ignored = sigaction()
        ignored.__sigaction_u.__sa_handler = SIG_IGN
        XCTAssertEqual(sigemptyset(&ignored.sa_mask), 0)
        let setStatus = sigaction(SIGUSR2, &ignored, nil)
        try XCTUnwrap(setStatus == 0 ? true : nil)
        defer { XCTAssertEqual(sigaction(SIGUSR2, &initial, nil), 0) }
        var lines: [String] = []
        let result = MCPFatalSignalReporter.installForLaunch(
            signals: [SIGUSR2], log: { lines.append($0) }, stackStep: { 0 })
        XCTAssertEqual(result.unavailableSignals, [SIGUSR2])
        XCTAssertEqual(result.stackStatus, 0)
        XCTAssertEqual(lines, ["fatal reporter incomplete: handlers unavailable [SIGUSR2]"])
        var current = sigaction()
        XCTAssertEqual(MacScopeReadSignalDisposition(SIGUSR2, &current), 0)
        let initialBits = ignored.__sigaction_u.__sa_handler.map { unsafeBitCast($0, to: UInt.self) } ?? 0
        let currentBits = current.__sigaction_u.__sa_handler.map { unsafeBitCast($0, to: UInt.self) } ?? 0
        XCTAssertEqual(currentBits, initialBits)
        XCTAssertEqual(current.sa_mask, ignored.sa_mask)
        XCTAssertEqual(current.sa_flags, ignored.sa_flags)
    }
}
