import Foundation
import Logging
import MCP
import Darwin

/// Narrow byte transport: the official SDK owns JSON-RPC and all MCP semantics.
/// One instance owns one explicitly selected process and is never reconnected.
actor BoundedSubprocessTransport: Transport {
    nonisolated let logger = Logger(label: "MacScope.ExternalMCP", factory: { _ in SwiftLogNoOpLogHandler() })

    private struct PendingWrite: Sendable {
        let id: UUID
        let data: Data
        let continuation: CheckedContinuation<Void, any Error>
    }

    private let configuration: MCPConnectionConfiguration
    private let failure: @Sendable (MCPClientError) async -> Void
    private let stream: AsyncThrowingStream<Data, any Error>
    private let incoming: AsyncThrowingStream<Data, any Error>.Continuation
    private var process: Process?
    private var inputPipe: Pipe?
    private var outputPipe: Pipe?
    private var errorPipe: Pipe?
    private var connected = false
    private var used = false
    private var stopped = false
    private var reader: Task<Void, Never>?
    private var errorReader: Task<Void, Never>?
    private var writer: Task<Void, Never>?
    private var writes: [PendingWrite] = []

    init(configuration: MCPConnectionConfiguration,
         failure: @escaping @Sendable (MCPClientError) async -> Void) {
        self.configuration = configuration; self.failure = failure
        let pair = AsyncThrowingStream<Data, any Error>.makeStream(
            bufferingPolicy: .bufferingOldest(configuration.limits.maximumBufferedMessages))
        self.stream = pair.stream; self.incoming = pair.continuation
    }

    func connect() async throws {
        guard !used else { throw MCPClientError.connectionBusy }
        used = true
        try await MCPExecutableValidation.validate(configuration)
        try Task.checkCancellation()
        guard !stopped else { throw MCPClientError.transportClosed }
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        let child = Process()
        child.executableURL = configuration.executableURL
        child.arguments = configuration.arguments
        child.environment = configuration.environment
        child.standardInput = stdin; child.standardOutput = stdout; child.standardError = stderr
        child.terminationHandler = { @Sendable [weak self] _ in
            Task { [weak self] in
                guard let self else { return }
                await self.fail(.childExited)
            }
        }
        process = child; inputPipe = stdin; outputPipe = stdout; errorPipe = stderr
        do {
            try setNonBlocking(stdout.fileHandleForReading.fileDescriptor)
            try setNonBlocking(stderr.fileHandleForReading.fileDescriptor)
            try setNonBlocking(stdin.fileHandleForWriting.fileDescriptor)
            guard fcntl(stdin.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) != -1
            else { throw MCPClientError.protocolFailure }
            try child.run()
            connected = true
            try? stdin.fileHandleForReading.close()
            try? stdout.fileHandleForWriting.close()
            try? stderr.fileHandleForWriting.close()
            reader = Task { [weak self] in
                guard let self else { return }
                await self.readLoop()
            }
            errorReader = Task { [weak self] in
                guard let self else { return }
                await self.drainErrorLoop()
            }
        } catch {
            closeHandles()
            process = nil
            incoming.finish(throwing: MCPClientError.permissionDenied)
            throw MCPClientError.permissionDenied
        }
    }

    func receive() -> AsyncThrowingStream<Data, any Error> { stream }

    func send(_ data: Data) async throws {
        guard connected else { throw MCPClientError.transportClosed }
        guard data.count <= configuration.limits.maximumMessageBytes else { throw MCPClientError.responseTooLarge }
        guard writes.count < configuration.limits.maximumPendingRequests + 4 else { throw MCPClientError.backpressure }
        var framed = data
        framed.append(10)
        try await withCheckedThrowingContinuation { continuation in
            writes.append(PendingWrite(id: UUID(), data: framed, continuation: continuation))
            if writer == nil {
                writer = Task { [weak self] in
                    guard let self else { return }
                    await self.writeLoop()
                }
            }
        }
    }

    func disconnect() async {
        stopped = true
        connected = false
        incoming.finish(throwing: MCPClientError.transportClosed)
        let tasks = [reader, errorReader, writer].compactMap { $0 }
        reader = nil; errorReader = nil; writer = nil
        tasks.forEach { $0.cancel() }
        rejectWrites(.transportClosed)
        for task in tasks { await task.value }
        if let child = process, child.isRunning {
            child.terminate()
            for _ in 0..<20 where child.isRunning { try? await Task.sleep(for: .milliseconds(25)) }
            if child.isRunning { _ = kill(child.processIdentifier, SIGKILL) }
        }
        process?.terminationHandler = nil
        closeHandles()
        process = nil
    }

    private func setNonBlocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags != -1, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != -1
        else { throw MCPClientError.protocolFailure }
    }

    private func fail(_ error: MCPClientError) {
        guard connected else { return }
        connected = false
        incoming.finish(throwing: error)
        reader?.cancel(); errorReader?.cancel(); writer?.cancel()
        rejectWrites(error)
        // Do not await teardown from the task being joined by teardown.
        let notify = failure
        Task { await notify(error) }
    }

    private func rejectWrites(_ error: MCPClientError) {
        let pending = writes
        writes.removeAll(keepingCapacity: false)
        for write in pending { write.continuation.resume(throwing: error) }
    }

    private func readLoop() async {
        guard let descriptor = outputPipe?.fileHandleForReading.fileDescriptor else { return }
        var bytes = [UInt8](repeating: 0, count: 8_192)
        var pending = Data()
        var windowStart = ContinuousClock.now
        var frameCount = 0
        while connected, !Task.isCancelled {
            let count = bytes.withUnsafeMutableBytes { systemRead(descriptor, $0.baseAddress!, $0.count) }
            if count == 0 { fail(pending.isEmpty ? .transportClosed : .malformedMessage); return }
            if count < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    do { try await Task.sleep(for: .milliseconds(2)) } catch { return }
                    continue
                }
                fail(.transportClosed); return
            }
            pending.append(contentsOf: bytes.prefix(count))
            while let newline = pending.firstIndex(of: 10) {
                let now = ContinuousClock.now
                if now - windowStart >= .seconds(1) { windowStart = now; frameCount = 0 }
                frameCount += 1
                guard frameCount <= configuration.limits.maximumFramesPerSecond else { fail(.backpressure); return }
                let line = Data(pending[..<newline])
                pending.removeSubrange(...newline)
                do { try MCPBoundaryValidation.validateFrame(line, limits: configuration.limits) }
                catch { fail((error as? MCPClientError) ?? .malformedMessage); return }
                switch incoming.yield(line) {
                case .enqueued: break
                case .dropped: fail(.backpressure); return
                case .terminated: fail(.transportClosed); return
                @unknown default: fail(.protocolFailure); return
                }
            }
            guard pending.count <= configuration.limits.maximumMessageBytes else { fail(.responseTooLarge); return }
            // Yield between chunks; notification floods cannot monopolize the actor.
            await Task.yield()
        }
    }

    private func drainErrorLoop() async {
        guard let descriptor = errorPipe?.fileHandleForReading.fileDescriptor else { return }
        var bytes = [UInt8](repeating: 0, count: 4_096)
        while connected, !Task.isCancelled {
            let count = bytes.withUnsafeMutableBytes { systemRead(descriptor, $0.baseAddress!, $0.count) }
            if count == 0 { return }
            if count < 0, errno != EAGAIN, errno != EWOULDBLOCK, errno != EINTR { return }
            // Discard without decoding or logging. Poll cadence also bounds diagnostic CPU use.
            do { try await Task.sleep(for: .milliseconds(count > 0 ? 1 : 5)) } catch { return }
        }
    }

    private func writeLoop() async {
        guard let descriptor = inputPipe?.fileHandleForWriting.fileDescriptor else { return }
        while connected, !Task.isCancelled, let next = writes.first {
            var offset = 0
            while offset < next.data.count, connected, !Task.isCancelled {
                let count = next.data.withUnsafeBytes {
                    safePipeWrite(descriptor, $0.baseAddress!.advanced(by: offset), $0.count - offset)
                }
                if count < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        do { try await Task.sleep(for: .milliseconds(2)) } catch { return }
                        continue
                    }
                    fail(.transportClosed); return
                }
                guard count > 0 else { fail(.transportClosed); return }
                offset += count
            }
            guard connected, !Task.isCancelled, writes.first?.id == next.id else { return }
            writes.removeFirst().continuation.resume()
        }
        writer = nil
    }

    private func closeHandles() {
        for pipe in [inputPipe, outputPipe, errorPipe].compactMap({ $0 }) {
            try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close()
        }
        inputPipe = nil; outputPipe = nil; errorPipe = nil
    }
}

private func systemRead(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
    Darwin.read(descriptor, buffer, count)
}

/// Avoid a global SIGPIPE disposition change in the host application.
private func safePipeWrite(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
    Darwin.write(descriptor, buffer, count)
}
