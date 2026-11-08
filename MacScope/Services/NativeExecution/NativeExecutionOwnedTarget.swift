import Darwin
import Foundation

struct NativeExecutionProcessObservation: Sendable {
    let anchor: DebuggerLocalProcessInstanceKey
    let path: String
    let status: UInt32

    static func read(processID: Int32) -> Self? {
        guard processID > 1, processID != getpid() else { return nil }
        var info = proc_bsdinfo()
        let count = withUnsafeMutablePointer(to: &info) {
            proc_pidinfo(processID, PROC_PIDTBSDINFO, 0, $0, Int32(MemoryLayout<proc_bsdinfo>.size))
        }
        guard count == MemoryLayout<proc_bsdinfo>.size, info.pbi_pid == UInt32(processID),
              let micros = UInt32(exactly: info.pbi_start_tvusec),
              let start = DebuggerProcessStartIdentity(seconds: info.pbi_start_tvsec, microseconds: micros) else { return nil }
        var bytes = [CChar](repeating: 0, count: 4096)
        let length = bytes.withUnsafeMutableBytes { proc_pidpath(processID, $0.baseAddress, UInt32($0.count)) }
        guard length > 0 else { return nil }
        let pathBytes = bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard let path = String(bytes: pathBytes, encoding: .utf8) else { return nil }
        return Self(anchor: DebuggerLocalProcessInstanceKey(processID: processID, startTime: start),
                    path: path, status: info.pbi_status)
    }
}

/// Opaque attachment authority minted only by the retained target after registry binding.
/// Reading an anchor is not enough to construct a permit for an arbitrary process.
struct NativeExecutionOwnedTargetPermit: Sendable {
    let anchor: DebuggerLocalProcessInstanceKey
    let path: String
    private let target: NativeExecutionOwnedTarget

    fileprivate init(anchor: DebuggerLocalProcessInstanceKey, path: String, target: NativeExecutionOwnedTarget) {
        self.anchor = anchor; self.path = path; self.target = target
    }

    func isCurrent() async -> Bool { await target.matches(anchor, path: path) }
}

/// Retains the one Foundation child through helper -> sandbox -> suspended original exec.
/// No method accepts an arbitrary PID or a target from the ordinary debugger.
actor NativeExecutionOwnedTarget: DebuggerOwnedInfrastructureRetainedProcessBinding {
    private let process: Process
    private let launcherLog: FileHandle
    private var attemptedLaunch = false
    private var launched = false
    private var retainedPID: Int32?
    private var initialAnchor: DebuggerLocalProcessInstanceKey?
    private var reaped = false

    private init(process: Process, launcherLog: FileHandle) {
        self.process = process
        self.launcherLog = launcherLog
    }

    @MainActor
    static func prepare(helper: URL, executable: String, jobDirectory: URL) throws -> NativeExecutionOwnedTarget {
        let logURL = jobDirectory.appendingPathComponent("launcher")
        let descriptor = Darwin.open(logURL.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw NativeExecutionError.unavailable("The private execution log could not be created.") }
        let log = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let process = Process()
        process.executableURL = helper
        process.arguments = [executable, jobDirectory.path]
        process.currentDirectoryURL = jobDirectory
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = log
        process.standardError = log
        return NativeExecutionOwnedTarget(process: process, launcherLog: log)
    }

    func launch() throws {
        try Task.checkCancellation()
        guard !attemptedLaunch else { throw NativeExecutionError.invalidRequest("The native target launch was already consumed.") }
        attemptedLaunch = true
        do {
            try process.run()
            launched = true
            retainedPID = process.processIdentifier
            initialAnchor = NativeExecutionProcessObservation.read(processID: process.processIdentifier)?.anchor
        } catch {
            if process.processIdentifier > 1 {
                launched = true
                retainedPID = process.processIdentifier
                initialAnchor = NativeExecutionProcessObservation.read(processID: process.processIdentifier)?.anchor
            }
            throw error
        }
    }

    func suspendedOriginal(path: String, timeout: Duration = .seconds(8)) async throws -> DebuggerLocalProcessInstanceKey {
        guard let initialAnchor else {
            throw NativeExecutionError.unavailable("The launched target has no captured kernel lifetime identity.")
        }
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            guard launched, process.isRunning, let retainedPID else {
                throw NativeExecutionError.unavailable("The confined launcher exited before the original executable was suspended.")
            }
            if let observed = NativeExecutionProcessObservation.read(processID: retainedPID) {
                if initialAnchor != observed.anchor {
                    throw NativeExecutionError.unavailable("The owned process instance changed during startup.")
                }
                if observed.path == path, observed.status == 4 { return observed.anchor }
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw NativeExecutionError.unavailable("The original executable did not reach a verified suspended startup state.")
    }

    func matches(_ anchor: DebuggerLocalProcessInstanceKey, path: String) -> Bool {
        guard launched, process.isRunning, retainedPID == anchor.processID,
              let observation = NativeExecutionProcessObservation.read(processID: anchor.processID) else { return false }
        return observation.anchor == anchor && observation.path == path
    }

    func attachmentPermit(registration: DebuggerOwnedInfrastructureRegistration,
                          path: String) throws -> NativeExecutionOwnedTargetPermit {
        guard registration.kind == .nativeFunctionTarget,
              matches(registration.instanceKey, path: path) else {
            throw NativeExecutionError.unavailable("The native target no longer matches its owned-process registration.")
        }
        return NativeExecutionOwnedTargetPermit(anchor: registration.instanceKey, path: path, target: self)
    }

    /// Kernel lifetime identity is checked immediately before signaling the retained child.
    @discardableResult
    func killIfStillOwned() -> Bool {
        guard launched, !reaped else { return true }
        guard process.isRunning else { return true }
        guard let retainedPID, process.processIdentifier == retainedPID,
              let initialAnchor,
              let observed = NativeExecutionProcessObservation.read(processID: retainedPID),
              initialAnchor == observed.anchor else { return false }
        return Darwin.kill(retainedPID, SIGKILL) == 0 || errno == ESRCH
    }

    func killAndReap() async -> Bool {
        if reaped { return true }
        if !launched {
            try? launcherLog.close()
            return true
        }
        _ = killIfStillOwned()
        guard let retainedPID, let initialAnchor else { return false }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while ContinuousClock.now < deadline {
            if let observed = NativeExecutionProcessObservation.read(processID: retainedPID),
               observed.anchor != initialAnchor { return false }
            // Attaching a debugger can consume the child's exit notification without updating
            // Foundation's cached isRunning. Settle the exact retained child in the kernel;
            // ECHILD plus ESRCH means another reaper already consumed this absent child.
            var status: Int32 = 0
            let waited = Darwin.waitpid(retainedPID, &status, WNOHANG)
            let alreadyReaped = waited == -1 && errno == ECHILD
                && Darwin.kill(retainedPID, 0) == -1 && errno == ESRCH
            // Traced children can report a stop without WUNTRACED; only an exit or
            // signal status consumes the child. A stop/continue event is not reap proof.
            let exitedOrSignaled = waited == retainedPID && (status & 0x7f) != 0x7f
            if exitedOrSignaled || alreadyReaped {
                reaped = true
                try? launcherLog.close()
                return true
            }
            if waited == -1 && errno != EINTR && errno != ECHILD { return false }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return false
    }

    func cleanupDiagnostic() -> String {
        let status = retainedPID.flatMap { NativeExecutionProcessObservation.read(processID: $0)?.status }
        return "Foundation running=\(process.isRunning), kernelStatus=\(String(describing: status))"
    }

    func retainedProcessIdentifierForInfrastructure() async -> Int32 { retainedPID ?? 0 }
    func retainedProcessIsRunningForInfrastructure() async -> Bool { launched && !reaped && process.isRunning }
    func retainedProcessDispositionForInfrastructure() async -> DebuggerOwnedInfrastructureRetainedProcessDisposition {
        if !launched { return .notLaunched }
        if reaped { return .exitedAndReaped }
        return process.isRunning ? .running : .unknown
    }
}
