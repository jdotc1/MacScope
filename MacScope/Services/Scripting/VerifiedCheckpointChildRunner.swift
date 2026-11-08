import Darwin
import Foundation

/// VA8: spawns a child MacScope in the `--headless-workspace-acceptance` `verified-checkpoint`
/// mode and returns what it wrote. The child opens no store and no session; it reads the saved
/// package with the pure package reader under a fresh installation ID and its own process ID.
///
/// This type only moves bytes and a process; it judges nothing. The caller decides whether the
/// result proves isolation.
struct VerifiedCheckpointChildResult: Sendable {
    /// Process ID of the child the runner started (never the caller's own).
    let pid: Int32
    let exitStatus: Int32
    /// Bytes of `<output>/result.json`, or nil when missing, unreadable or over the cap.
    let resultJSON: Data?
    let stderrFirstLine: String
    let timedOut: Bool
    /// Private temp directory holding request.json, expectation.json and the child output.
    let directory: URL
}

protocol VerifiedCheckpointChildRunning: Sendable {
    func run(executable: URL, workspace: URL, expectation: Data, timeout: TimeInterval) async throws -> VerifiedCheckpointChildResult
}

struct VerifiedCheckpointChildRunnerError: Error, CustomStringConvertible {
    let description: String
}

struct ProcessVerifiedCheckpointChildRunner: VerifiedCheckpointChildRunning {
    nonisolated static let maximumResultBytes = 1_048_576
    nonisolated static let maximumDrainBytes = 65_536
    nonisolated static let defaultTimeout: TimeInterval = 25
    /// Pinned equal to `HeadlessWorkspaceAcceptance.selector` by a test.
    nonisolated static let headlessSelector = "--headless-workspace-acceptance"

    /// Exactly the keys the headless action accepts for `verified-checkpoint`.
    nonisolated static func requestJSON(workspace: URL, output: URL, expectation: URL) throws -> Data {
        try ScriptValue.object([
            "action": .string("verified-checkpoint"), "workspace": .string(workspace.path),
            "output": .string(output.path), "expectation": .string(expectation.path),
        ]).jsonData()
    }

    /// A minimal environment: no XCTest configuration, no DYLD_*, no MCP harness switches.
    nonisolated static func scrubbedEnvironment(from source: [String: String] = ProcessInfo.processInfo.environment)
        -> [String: String] {
        var out: [String: String] = [:]
        for key in ["PATH", "HOME", "TMPDIR"] {
            if let value = source[key] { out[key] = value }
        }
        return out
    }

    func run(executable: URL, workspace: URL, expectation: Data, timeout: TimeInterval) async throws -> VerifiedCheckpointChildResult {
        guard timeout > 0, timeout.isFinite else { throw VerifiedCheckpointChildRunnerError(description: "timeout must be positive and finite") }
        try Task.checkCancellation()
        let manager = FileManager.default
        let directory = manager.temporaryDirectory
            .appendingPathComponent("macscope-vcp-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        let expectationURL = directory.appendingPathComponent("expectation.json")
        let requestURL = directory.appendingPathComponent("request.json")
        let output = directory.appendingPathComponent("out", isDirectory: true)
        try expectation.write(to: expectationURL)
        try Self.requestJSON(workspace: workspace, output: output, expectation: expectationURL).write(to: requestURL)

        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = executable
        process.arguments = [Self.headlessSelector, requestURL.path]
        process.environment = Self.scrubbedEnvironment()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = stdout
        process.standardError = stderr
        do { try process.run() } catch {
            throw VerifiedCheckpointChildRunnerError(description: "cannot launch child: \(error.localizedDescription)")
        }
        let pid = process.processIdentifier
        let control = ChildControl(process: process, pid: pid)
        let stderrBox = DrainBox()
        let stdoutHandle = stdout.fileHandleForReading
        let stderrHandle = stderr.fileHandleForReading

        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    let drains = DispatchGroup()
                    drains.enter()
                    DispatchQueue.global().async {
                        _ = Self.drain(stdoutHandle, cap: Self.maximumDrainBytes)
                        drains.leave()
                    }
                    drains.enter()
                    DispatchQueue.global().async {
                        stderrBox.set(Self.drain(stderrHandle, cap: Self.maximumDrainBytes))
                        drains.leave()
                    }
                    DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { control.expire() }
                    process.waitUntilExit()
                    drains.wait()
                    continuation.resume()
                }
            }
        } onCancel: {
            control.cancel()
        }
        try? stdoutHandle.close()
        try? stderrHandle.close()
        if control.wasCancelled { throw CancellationError() }

        let resultURL = output.appendingPathComponent("result.json")
        let result = Self.boundedRead(resultURL, maximumBytes: Self.maximumResultBytes)
        let firstLine = String(decoding: stderrBox.data, as: UTF8.self)
            .split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: true).first.map(String.init) ?? ""
        return VerifiedCheckpointChildResult(
            pid: pid, exitStatus: process.terminationStatus, resultJSON: result,
            stderrFirstLine: String(firstLine.prefix(512)), timedOut: control.didTimeOut, directory: directory)
    }

    /// Reads at most `maximumBytes`; nil when missing, unreadable or larger.
    nonisolated static func boundedRead(_ url: URL, maximumBytes: Int) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: maximumBytes + 1), data.count <= maximumBytes else { return nil }
        return data
    }

    private static func drain(_ handle: FileHandle, cap: Int) -> Data {
        var kept = Data()
        while true {
            guard let chunk = try? handle.read(upToCount: 4_096), !chunk.isEmpty else { break }
            if kept.count < cap { kept.append(chunk.prefix(cap - kept.count)) }
        }
        return kept
    }
}

private final class DrainBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Data()
    func set(_ data: Data) { lock.lock(); value = data; lock.unlock() }
    var data: Data { lock.lock(); defer { lock.unlock() }; return value }
}

/// Terminates the owned child on timeout or cancellation: SIGTERM, then SIGKILL after 0.25 s.
private final class ChildControl: @unchecked Sendable {
    private let lock = NSLock()
    private let process: Process
    private let pid: Int32
    private var timedOut = false
    private var cancelled = false

    init(process: Process, pid: Int32) { self.process = process; self.pid = pid }

    var didTimeOut: Bool { lock.lock(); defer { lock.unlock() }; return timedOut }
    var wasCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }

    func expire() {
        guard process.isRunning else { return }
        lock.lock(); timedOut = true; lock.unlock()
        terminate()
    }

    func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
        terminate()
    }

    private func terminate() {
        guard process.isRunning else { return }
        process.terminate()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.25) { [process, pid] in
            if process.isRunning { kill(pid, SIGKILL) }
        }
    }
}
