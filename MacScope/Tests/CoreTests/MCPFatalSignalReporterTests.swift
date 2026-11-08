import Darwin
import Foundation
import MacScopeChildProcessC
import MacScopeFatalSignalC
import XCTest
@testable import MacScope

private final class AlternateStackObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var value: (Int32, Int32, Int, Int, UInt, UInt)?
    func record(_ first: stack_t, _ second: stack_t, firstStatus: Int32, secondStatus: Int32) {
        lock.lock()
        value = (firstStatus, secondStatus, Int(first.ss_flags), Int(first.ss_size),
                 UInt(bitPattern: first.ss_sp), UInt(bitPattern: second.ss_sp))
        lock.unlock()
    }
    func snapshot() -> (Int32, Int32, Int, Int, UInt, UInt)? {
        lock.lock(); defer { lock.unlock() }; return value
    }
}

@MainActor
final class MCPFatalSignalReporterTests: XCTestCase {
    private let ordinary: [(MCPLaunchState, String)] = [
        (.starting, "starting"), (.openingPackage, "openingPackage"),
        (.fingerprinting, "fingerprinting"), (.verifying, "verifying"),
        (.binding, "binding"), (.ready, "ready"), (.failed, "failed")
    ]
    private let phases: [(AnalysisPhase, String)] = [
        (.load, "load"), (.decode, "decode"), (.functionDiscovery, "functionDiscovery"),
        (.listing, "listing"), (.jumpTables, "jumpTables"), (.controlFlow, "controlFlow"),
        (.dataReferences, "dataReferences"), (.switchHints, "switchHints"),
        (.diagnostics, "diagnostics"), (.rehydrate, "rehydrate")
    ]
    private let signals: [(Int32, String)] = [
        (SIGSEGV, "SIGSEGV"), (SIGBUS, "SIGBUS"), (SIGILL, "SIGILL"),
        (SIGFPE, "SIGFPE"), (SIGTRAP, "SIGTRAP"), (SIGABRT, "SIGABRT"),
        (SIGSYS, "SIGSYS"), (SIGXCPU, "SIGXCPU"), (SIGXFSZ, "SIGXFSZ")
    ]

    private func bytes(_ signal: Int32, _ slot: Int, capacity: Int = 256) -> [UInt8] {
        var storage = [CChar](repeating: 0x55, count: max(capacity, 0) + 8)
        let count = storage.withUnsafeMutableBufferPointer {
            MCPFatalSignalReporter.formatReport(signal: signal, slot: slot,
                                                 into: $0.baseAddress!, capacity: capacity)
        }
        XCTAssertGreaterThanOrEqual(count, 0)
        XCTAssertLessThanOrEqual(count, max(capacity, 0))
        XCTAssertTrue(storage.dropFirst(max(capacity, 0)).allSatisfy { $0 == 0x55 })
        return storage.prefix(count).map { UInt8(bitPattern: $0) }
    }

    func testS1ExactStatesAndAllPhaseLines() {
        for (state, name) in ordinary {
            let expected = "MacScope MCP: terminated by signal SIGSEGV (\(SIGSEGV)) in state \(name)\n"
            XCTAssertEqual(bytes(SIGSEGV, state.slot), Array(expected.utf8))
        }
        for (index, item) in phases.enumerated() {
            XCTAssertEqual(MCPLaunchState.analyzing(item.0).slot, 16 + index)
            let expected = "MacScope MCP: terminated by signal SIGSEGV (\(SIGSEGV)) in state analyzing (phase \(item.1))\n"
            XCTAssertEqual(bytes(SIGSEGV, 16 + index), Array(expected.utf8))
        }
        XCTAssertEqual(bytes(SIGABRT, 99),
                       Array("MacScope MCP: terminated by signal SIGABRT (\(SIGABRT)) in state unknown\n".utf8))
    }

    func testS2ExactSignalNamesAndUnknownNumbers() {
        for (signal, name) in signals {
            XCTAssertEqual(bytes(signal, MCPLaunchState.ready.slot),
                           Array("MacScope MCP: terminated by signal \(name) (\(signal)) in state ready\n".utf8))
        }
        for signal in [Int32(0), -1, Int32.min, Int32.max] {
            XCTAssertEqual(bytes(signal, -1),
                           Array("MacScope MCP: terminated by signal UNKNOWN (\(signal)) in state unknown\n".utf8))
        }
    }

    func testS3LongestLineAndEveryTruncationBoundary() {
        let slots = ordinary.map { $0.0.slot } + phases.map { MCPLaunchState.analyzing($0.0).slot }
        var longest = 0
        for (signal, _) in signals {
            for slot in slots {
                let full = bytes(signal, slot)
                longest = max(longest, full.count)
                XCTAssertLessThan(full.count, 256)
                for cap in 0...full.count {
                    XCTAssertEqual(bytes(signal, slot, capacity: cap), Array(full.prefix(cap)))
                }
            }
        }
        XCTAssertGreaterThan(longest, 0)
        XCTAssertEqual(bytes(SIGSEGV, 0, capacity: -1), [])
    }

    func testS4ExactReportedSignalSet() {
        XCTAssertEqual(MCPFatalSignalReporter.reportedSignals, signals.map(\.0))
        let excluded: Set<Int32> = [SIGPIPE, SIGCHLD, SIGKILL, SIGSTOP, SIGTERM, SIGHUP, SIGINT]
        XCTAssertTrue(Set(MCPFatalSignalReporter.reportedSignals).isDisjoint(with: excluded))
    }

    private func readAction(_ signal: Int32) throws -> sigaction {
        var value = sigaction()
        let status = MacScopeReadSignalDisposition(signal, &value)
        XCTAssertEqual(status, 0)
        return try XCTUnwrap(status == 0 ? value : nil)
    }

    private func handlerBits(_ value: sigaction) -> UInt {
        value.__sigaction_u.__sa_handler.map { unsafeBitCast($0, to: UInt.self) } ?? 0
    }

    private func assertSameAction(_ left: sigaction, _ right: sigaction,
                                  file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(handlerBits(left), handlerBits(right), file: file, line: line)
        XCTAssertEqual(left.sa_mask, right.sa_mask, file: file, line: line)
        XCTAssertEqual(left.sa_flags, right.sa_flags, file: file, line: line)
    }

    func testS5DefaultOnlyInstallProtectedSignalsAndRestore() throws {
        let initial = try readAction(SIGUSR2)
        try XCTSkipIf(initial.__sigaction_u.__sa_handler != nil || initial.sa_flags & SA_SIGINFO != 0,
                      "Preserve a handler already owned by the test host")
        let pipe = try readAction(SIGPIPE)
        let child = try readAction(SIGCHLD)
        let saved = MCPFatalSignalReporter.install(signals: [SIGUSR2, SIGPIPE, SIGCHLD, SIGKILL, SIGSTOP])
        defer { MCPFatalSignalReporter.restore(saved) }
        XCTAssertEqual(Set(saved.keys), Set([SIGUSR2]))
        let installed = try readAction(SIGUSR2)
        XCTAssertNotNil(installed.__sigaction_u.__sa_handler)
        XCTAssertNotEqual(installed.sa_flags & SA_ONSTACK, 0)
        // Darwin's sigaction read-back does not expose SA_RESETHAND.
        XCTAssertTrue(MCPFatalSignalReporter.install(signals: [SIGUSR2]).isEmpty)
        assertSameAction(try readAction(SIGPIPE), pipe)
        assertSameAction(try readAction(SIGCHLD), child)
        MCPFatalSignalReporter.restore(saved)
        let restored = try readAction(SIGUSR2)
        XCTAssertNil(restored.__sigaction_u.__sa_handler)
        assertSameAction(restored, initial)
        assertSameAction(try readAction(SIGPIPE), pipe)
        assertSameAction(try readAction(SIGCHLD), child)
    }

    func testS6AlternateStackIsThreadLocalAndIdempotent() throws {
        let done = DispatchSemaphore(value: 0)
        let observation = AlternateStackObservation()
        let thread = Thread {
            MCPFatalSignalReporter.prepareAlternateStack()
            var first = stack_t()
            let firstStatus = MacScopeReadAlternateSignalStack(&first)
            MCPFatalSignalReporter.prepareAlternateStack()
            var second = stack_t()
            let secondStatus = MacScopeReadAlternateSignalStack(&second)
            observation.record(first, second, firstStatus: firstStatus, secondStatus: secondStatus)
            done.signal()
        }
        thread.start()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        let result = try XCTUnwrap(observation.snapshot())
        XCTAssertEqual(result.0, 0)
        XCTAssertEqual(result.1, 0)
        XCTAssertEqual(result.2 & Int(SS_DISABLE), 0)
        XCTAssertGreaterThanOrEqual(result.3, Int(SIGSTKSZ))
        XCTAssertNotEqual(result.4, 0)
        XCTAssertEqual(result.4, result.5)
    }
}
