import Darwin
import Foundation
import MacScopeFatalSignalC

enum MCPLaunchState: Sendable, Equatable {
    case starting, openingPackage, fingerprinting, analyzing(AnalysisPhase)
    case verifying, binding, ready, failed

    var slot: Int {
        switch self {
        case .starting: 0
        case .openingPackage: 1
        case .fingerprinting: 2
        case .verifying: 3
        case .binding: 4
        case .ready: 5
        case .failed: 6
        case .analyzing(let phase): 16 + (AnalysisPhase.allCases.firstIndex(of: phase) ?? 0)
        }
    }
}

enum MCPFatalSignalReporter {
    static let reportedSignals: [Int32] = [
        SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGABRT, SIGSYS, SIGXCPU, SIGXFSZ
    ]

    // Keep every shared-C-state call in this Swift file, including optimized builds.
    @inline(never)
    static func note(_ state: MCPLaunchState) {
        MacScopeFatalSignalNote(Int32(state.slot))
    }

    @inline(never)
    static func install(signals: [Int32] = reportedSignals) -> [Int32: sigaction] {
        var previous: [Int32: sigaction] = [:]
        for signo in signals {
            guard signo != SIGPIPE, signo != SIGCHLD, signo != SIGKILL, signo != SIGSTOP else { continue }
            var action = sigaction()
            if MacScopeInstallFatalSignalHandler(signo, &action) == 0 {
                previous[signo] = action
            }
        }
        return previous
    }

    @inline(never)
    static func restore(_ previous: [Int32: sigaction]) {
        for (signo, saved) in previous {
            var action = saved
            _ = MacScopeRestoreSignalAction(signo, &action)
        }
    }

    struct LaunchResult {
        let unavailableSignals: [Int32]
        let stackStatus: Int32
    }

    private static let stackFailureLock = NSLock()
    nonisolated(unsafe) private static var didReportStackFailure = false

    @discardableResult
    static func installForLaunch(
        signals: [Int32] = reportedSignals,
        log: (String) -> Void = MCPStartupLog.line,
        installStep: ([Int32]) -> [Int32: sigaction] = { install(signals: $0) },
        stackStep: (() -> Int32)? = nil
    ) -> LaunchResult {
        // An explicit stackStep is the existing injection seam: never install a global hook.
        // The production default is used by the headless launch, not by ordinary entries.
        let hookStatus = stackStep == nil ? installThreadStackHook() : 0
        if stackStep == nil { reportThreadStackFailures(log: log) }
        let installed = installStep(signals)
        let missing = signals.filter { installed[$0] == nil }
        let stackStatus = stackStep.map { $0() } ?? hookStatus
        var issues: [String] = []
        if !missing.isEmpty {
            issues.append("handlers unavailable [" + missing.map(signalName).joined(separator: ",") + "]")
        }
        if stackStatus != 0 { issues.append("alternate stack unavailable") }
        if !issues.isEmpty { log("fatal reporter incomplete: " + issues.joined(separator: "; ")) }
        return LaunchResult(unavailableSignals: missing, stackStatus: stackStatus)
    }

    // This flag and lock are for ordinary Swift entries, never the signal handler.
    @discardableResult
    static func prepareAlternateStack(log: (String) -> Void = MCPStartupLog.line) -> Int32 {
        reportThreadStackFailures(log: log)
        let status = ensureAlternateStack()
        if status != 0 {
            stackFailureLock.lock()
            let shouldReport = !didReportStackFailure
            didReportStackFailure = true
            stackFailureLock.unlock()
            if shouldReport { log("fatal reporter incomplete: alternate stack unavailable at worker entry") }
        }
        return status
    }

    @inline(never)
    private static func ensureAlternateStack() -> Int32 {
        MacScopeEnsureAlternateSignalStack()
    }

    private static let threadHookLock = NSLock()

    @inline(never)
    private static func installThreadStackHook() -> Int32 {
        threadHookLock.lock()
        defer { threadHookLock.unlock() }
        return MacScopeInstallThreadStackHook()
    }

    @inline(never)
    private static func reportThreadStackFailures(log: (String) -> Void) {
        let warnings = MacScopeTakeThreadStackWarnings()
        if warnings & 1 != 0 {
            log("fatal reporter incomplete: alternate stack unavailable in thread hook")
        }
        if warnings & 2 != 0 {
            log("fatal reporter incomplete: thread hook ownership changed")
        }
    }

    // Test seams deliberately execute in the app's shared-C-state translation unit.
    @inline(never)
    static func beginThreadStackProbeForTesting() -> Int32 {
        threadHookLock.lock()
        defer { threadHookLock.unlock() }
        return MacScopeBeginThreadStackProbe()
    }

    @inline(never)
    static func installThreadStackHookForTesting() -> Int32 { installThreadStackHook() }

    @inline(never)
    static func endThreadStackProbeForTesting() -> Int32 {
        threadHookLock.lock()
        defer { threadHookLock.unlock() }
        return MacScopeEndThreadStackProbe()
    }

    @inline(never)
    static func setThreadStackProbeArmedForTesting(_ armed: Bool) { MacScopeSetThreadStackProbeArmed(armed ? 1 : 0) }

    @inline(never)
    static func threadStackProbeCountForTesting(_ event: UInt32) -> Int32 {
        MacScopeThreadStackProbeCount(event)
    }

    @inline(never)
    static func threadStackProbePreparedForTesting() -> Int32 { MacScopeThreadStackProbePrepared() }

    @inline(never)
    static func threadStackSawStartForTesting() -> Bool { MacScopeThreadStackSawStart() != 0 }

    private static func signalName(_ signal: Int32) -> String {
        switch signal {
        case SIGSEGV: "SIGSEGV"
        case SIGBUS: "SIGBUS"
        case SIGILL: "SIGILL"
        case SIGFPE: "SIGFPE"
        case SIGTRAP: "SIGTRAP"
        case SIGABRT: "SIGABRT"
        case SIGSYS: "SIGSYS"
        case SIGXCPU: "SIGXCPU"
        case SIGXFSZ: "SIGXFSZ"
        case SIGUSR2: "SIGUSR2"
        default: "UNKNOWN"
        }
    }

    static func formatReport(signal: Int32, slot: Int,
                             into buffer: UnsafeMutablePointer<CChar>, capacity: Int) -> Int {
        guard capacity > 0 else { return 0 }
        return Int(MacScopeFatalSignalFormat(signal, Int32(clamping: slot), buffer, capacity))
    }
}
