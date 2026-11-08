import Darwin
import Foundation

struct RegenerationToolResult: Sendable {
    let exitStatus: Int32
    let stdout: Data
    let stderr: Data
    let stdoutPath: String
    let stderrPath: String
    let elapsedSeconds: Double
    let stopReason: String?
    let cleanupComplete: Bool

    func requireSuccess() throws {
        guard exitStatus == 0, stopReason == nil, cleanupComplete else {
            throw RegenerationError.toolFailed("exit \(exitStatus), \(stopReason ?? "tool failure"), cleanupComplete=\(cleanupComplete); logs: \(stdoutPath), \(stderrPath)")
        }
    }
}

/// Runs only developer tools selected by the caller, through the shared storage guard. Logs stay
/// outside deterministic project content. No shell command text or target executable is accepted.
struct RegenerationToolRunner: Sendable {
    var guardURL = URL(fileURLWithPath: NSHomeDirectory() + "/Developer/Codex/storage-guard/bin/storage-guard")
    var timeout: TimeInterval = 30
    var maximumOutputBytes: UInt64 = 8_388_608
    var logRoot: URL? = nil

    /// Check the destination volume before passive copies or tool logs allocate disk space.
    /// Developer-tool execution remains separately supervised by `storage-guard run`.
    func checkStorage(at directory: URL) throws {
        guard directory.isFileURL, directory.path.hasPrefix("/"),
              FileManager.default.isExecutableFile(atPath: guardURL.path) else {
            throw RegenerationError.invalidInput("mandatory storage guard is unavailable")
        }
        let process = Process()
        process.executableURL = guardURL
        process.arguments = ["check", "--path", directory.path]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw RegenerationError.toolFailed("storage guard refused destination allocation (exit \(process.terminationStatus))")
        }
    }

    func run(executable: URL, arguments: [String], workingDirectory: URL) throws -> RegenerationToolResult {
        try Task.checkCancellation()
        guard executable.isFileURL, executable.path.hasPrefix("/"),
              FileManager.default.isExecutableFile(atPath: guardURL.path),
              timeout.isFinite, timeout > 0, timeout <= 120 else {
            throw RegenerationError.invalidInput("developer tool or mandatory storage guard is unavailable")
        }
        // This is a closed tool boundary, not a general process runner for recovered binaries.
        let isXcrun = executable.path == "/usr/bin/xcrun"
        let appleTools: Set<String> = ["momc", "xcstringstool", "actool", "ibtool", "clang", "xcodebuild"]
        guard (isXcrun && arguments.first.map(appleTools.contains) == true)
                || executable.lastPathComponent == "xcodegen" else {
            throw RegenerationError.invalidInput("tool is outside the regeneration developer-tool set")
        }
        let logDirectory = (logRoot ?? workingDirectory).appendingPathComponent("ToolRuns/" + UUID().uuidString.lowercased(), isDirectory: true)
        try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        let outURL = logDirectory.appendingPathComponent("stdout.log"), errURL = logDirectory.appendingPathComponent("stderr.log")
        let out = try outputHandle(outURL), err = try outputHandle(errURL)
        defer { try? out.close(); try? err.close() }
        let process = Process()
        process.executableURL = guardURL
        process.arguments = ["run", "--", executable.path] + arguments
        process.currentDirectoryURL = workingDirectory
        var environment = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("DYLD_") && !$0.key.hasPrefix("LD_") }
        let oldPath = environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
        environment["PATH"] = NSHomeDirectory() + "/.local/bin:" + oldPath
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = out; process.standardError = err
        let started = ProcessInfo.processInfo.systemUptime
        try process.run()
        var reason: String?, stoppedAt: TimeInterval?
        while process.isRunning {
            let now = ProcessInfo.processInfo.systemUptime
            if reason == nil {
                if Task.isCancelled { reason = "cancelled" }
                else if now - started > timeout { reason = "timeout" }
                else if size(outURL) > maximumOutputBytes || size(errURL) > maximumOutputBytes { reason = "outputLimit" }
                if reason != nil {
                    stoppedAt = now
                    // The guard forwards termination to its owned process group and performs cleanup.
                    process.terminate()
                }
            } else if let stoppedAt, now - stoppedAt > 10 {
                // Do not kill the guard and orphan a tool group. Failure retains its PID/logs;
                // publication is refused unless the owning guard actually completes cleanup.
                reason = "cleanupIncomplete(pid=\(process.processIdentifier))"
                break
            }
            Thread.sleep(forTimeInterval: 0.025)
        }
        let complete = !process.isRunning
        if complete { process.waitUntilExit() }
        if size(outURL) > maximumOutputBytes || size(errURL) > maximumOutputBytes { reason = reason ?? "outputLimit" }
        let output = try boundedBytes(outURL), errors = try boundedBytes(errURL)
        return .init(exitStatus: complete ? process.terminationStatus : -1, stdout: output, stderr: errors,
            stdoutPath: outURL.path, stderrPath: errURL.path,
            elapsedSeconds: ProcessInfo.processInfo.systemUptime - started, stopReason: reason,
            cleanupComplete: complete)
    }

    private func outputHandle(_ url: URL) throws -> FileHandle {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RegenerationError.invalidPath("could not create developer-tool log") }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    private func size(_ url: URL) -> UInt64 {
        (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).flatMap { $0 >= 0 ? UInt64($0) : nil } ?? 0
    }

    private func boundedBytes(_ url: URL) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RegenerationError.invalidPath("could not read developer-tool log") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        return try file.read(upToCount: Int(min(maximumOutputBytes, UInt64(Int.max)))) ?? Data()
    }
}
