import Foundation

struct NativeExecutionConfiguration: Sendable {
    let helperURL: URL
    let programURL: URL
    let workRoot: URL

    static func production() throws -> Self {
        guard let executable = Bundle.main.executableURL,
              let program = Bundle.main.url(forResource: "NativeLLDBCallProgram", withExtension: "py") else {
            throw NativeExecutionError.unavailable("Native function execution is not included in this app build.")
        }
        return Self(helperURL: executable.deletingLastPathComponent().appendingPathComponent("NativeExecutionRunner").resolvingSymlinksInPath(),
            programURL: program,
            workRoot: FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Developer/MacScope/NativeFunctionRuns", isDirectory: true))
    }
}

/// App-lifetime owner: one native-call job across every document. Ordinary debugger state is
/// independent, while the existing registry/interlock graph owns both new process instances.
actor NativeExecutionCoordinator {
    private final class Run {
        let request: NativeFunctionCallRequest
        let directory: URL
        var target: NativeExecutionOwnedTarget?
        var token: DebuggerOwnedInfrastructureSpawnToken?
        var claim: DebuggerOwnedInfrastructureLaunchClaim?
        var registration: DebuggerOwnedInfrastructureRegistration?
        var attemptedRegistration = false
        var adapter: PersistentLLDBCLIAdapter?
        var session: NativeExecutionLLDBSession?
        var runtimeAddress: UInt64?
        var stopOutcome: NativeExecutionOutcome?
        var cleanupUnresolved = false
        var cleanupDiagnostics: [String] = []
        var totalWatchdog: Task<Void, Never>?
        var callWatchdog: Task<Void, Never>?

        init(request: NativeFunctionCallRequest, directory: URL) {
            self.request = request
            self.directory = directory
        }
    }

    private let registry: DebuggerOwnedInfrastructureRegistry
    private let configured: NativeExecutionConfiguration?
    private var active: Run?

    init(registry: DebuggerOwnedInfrastructureRegistry, configuration: NativeExecutionConfiguration? = nil) {
        self.registry = registry
        configured = configuration
    }

    func run(_ request: NativeFunctionCallRequest) async throws -> NativeFunctionCallResult {
        try request.validate()
        try Task.checkCancellation()
        guard active == nil else {
            if active?.cleanupUnresolved == true { throw NativeExecutionError.cleanupUnresolved }
            throw NativeExecutionError.busy
        }
        try requireUnchangedSource(request.image)
        let configuration = try configured ?? .production()
        guard FileManager.default.isExecutableFile(atPath: configuration.helperURL.path) else {
            throw NativeExecutionError.unavailable("The native execution helper is unavailable in this app build.")
        }
        try FileManager.default.createDirectory(at: configuration.workRoot, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let directory = configuration.workRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let run = Run(request: request, directory: directory)
        active = run
        run.totalWatchdog = Task { [weak self, id = request.id] in
            do { try await Task.sleep(for: .seconds(30)) } catch { return }
            await self?.stop(id: id, outcome: .timedOut)
        }
        let provisional = await withTaskCancellationHandler {
            await execute(run, configuration: configuration)
        } onCancel: {
            Task { await self.cancel(requestID: request.id) }
        }
        run.totalWatchdog?.cancel()
        run.callWatchdog?.cancel()
        // Cleanup must finish even when the caller's Task has been cancelled.
        let cleanup = Task.detached { await self.cleanup(runID: request.id) }
        let confirmed = await cleanup.value
        run.cleanupUnresolved = !confirmed
        let outcome = run.stopOutcome ?? provisional.outcome
        let diagnostics = provisional.diagnostics + run.cleanupDiagnostics + (confirmed ? [] : [NativeExecutionError.cleanupUnresolved.localizedDescription])
        if confirmed {
            active = nil
            try? FileManager.default.removeItem(at: directory)
        }
        return NativeFunctionCallResult(requestID: request.id, imageUUID: request.image.uuid, outcome: outcome,
            runtimeFunctionAddress: provisional.runtimeFunctionAddress, returnValue: provisional.returnValue,
            memory: provisional.memory, diagnostics: diagnostics, faultProgramCounter: provisional.faultProgramCounter,
            cleanupConfirmed: confirmed)
    }

    func cancel(requestID: UUID) async { await stop(id: requestID, outcome: .cancelled) }

    private func execute(_ run: Run, configuration: NativeExecutionConfiguration) async -> NativeFunctionCallResult {
        let request = run.request
        do {
            let program = try Data(contentsOf: configuration.programURL)
            guard program.count <= 65_536 else { throw NativeExecutionError.unavailable("The native program exceeds its bound.") }
            let target = try await NativeExecutionOwnedTarget.prepare(helper: configuration.helperURL,
                executable: request.image.canonicalPath, jobDirectory: run.directory)
            run.target = target
            try ensureActive(run)
            run.token = try await registry.beginSpawn(kind: .nativeFunctionTarget)
            guard let token = run.token else { throw NativeExecutionError.unavailable("Native target ownership could not be allocated.") }
            run.claim = try await registry.beginLaunchAttempt(token)
            try ensureActive(run)
            try requireUnchangedSource(request.image)
            try await target.launch()
            let anchor = try await target.suspendedOriginal(path: request.image.canonicalPath)
            try ensureActive(run)
            try requireUnchangedSource(request.image)
            guard let claim = run.claim else { throw NativeExecutionError.unavailable("Native target launch claim changed.") }
            run.attemptedRegistration = true
            run.registration = try await registry.registerSpawnedProcess(claim, retainedProcess: target)
            guard let registration = run.registration else { throw NativeExecutionError.unavailable("Native target registration changed.") }
            let permit = try await target.attachmentPermit(registration: registration, path: request.image.canonicalPath)
            try ensureActive(run)
            let toolchain = await MainActor.run { XcodeLLDBCommandLineAdapter.discoverLLDBToolchain() }
            guard let toolchain else { throw NativeExecutionError.unavailable("Select an installed Xcode toolchain with LLDB to run functions.") }
            let construction = try await NativeExecutionLLDBSession.make(toolchain: toolchain, registry: registry,
                jobDirectory: run.directory, permit: permit, request: request)
            let session: NativeExecutionLLDBSession
            switch construction {
            case .ready(let acquired): session = acquired; run.session = acquired; run.adapter = await acquired.retainedAdapter()
            case .unresolved(let adapter): run.adapter = adapter; throw NativeExecutionError.cleanupUnresolved
            }
            try ensureActive(run)
            guard await target.matches(anchor, path: request.image.canonicalPath) else {
                throw NativeExecutionError.unavailable("The suspended executable instance changed before debugger attachment.")
            }
            run.runtimeAddress = try await session.prepare(programSource: program)
            try ensureActive(run)
            try requireUnchangedSource(request.image)
            guard await target.matches(anchor, path: request.image.canonicalPath) else {
                throw NativeExecutionError.unavailable("The executable instance changed before the call.")
            }
            run.callWatchdog = Task { [weak self, id = request.id, seconds = request.timeoutSeconds] in
                do { try await Task.sleep(for: .seconds(seconds)) } catch { return }
                await self?.stop(id: id, outcome: .timedOut)
            }
            let result = try await session.invokeAndCollect()
            run.callWatchdog?.cancel()
            return result
        } catch {
            run.callWatchdog?.cancel()
            let outcome: NativeExecutionOutcome = run.stopOutcome ?? (error is CancellationError ? .cancelled : .failed)
            let helperDiagnostic = launcherDiagnostic(at: run.directory)
            return NativeFunctionCallResult(requestID: request.id, imageUUID: request.image.uuid, outcome: outcome,
                runtimeFunctionAddress: run.runtimeAddress, returnValue: nil, memory: [],
                diagnostics: [error.localizedDescription] + helperDiagnostic, faultProgramCounter: nil, cleanupConfirmed: false)
        }
    }

    private func stop(id: UUID, outcome: NativeExecutionOutcome) async {
        guard let run = active, run.request.id == id else { return }
        if run.stopOutcome == nil { run.stopOutcome = outcome }
        if let target = run.target { await target.killIfStillOwned() }
        if let adapter = run.adapter { _ = await Self.retireOwnedAdapter(adapter) }
    }

    /// The caller may be the watchdog task that execute() cancels as soon as the
    /// interrupted exchange returns. Its cancellation must never abort exit/reap proof.
    static func retireOwnedAdapter(_ adapter: PersistentLLDBCLIAdapter) async -> PersistentLLDBCLIShutdownReceipt {
        let retirement = Task.detached { await adapter.retireRetainedAdapterWithoutDebuggerCommand() }
        return await retirement.value
    }

    private func cleanup(runID: UUID) async -> Bool {
        guard let run = active, run.request.id == runID else { return false }
        if let session = run.session {
            do { try await session.destroyOwnedTarget() }
            catch { run.cleanupDiagnostics.append("Native debugger target teardown: \(error.localizedDescription)") }
        }
        // LLDB can retain a killed inferior in a debugger stop. Signal our owned target
        // first, then retire its debugger before waiting for the child's final exit/reap.
        if let target = run.target { await target.killIfStillOwned() }
        var adapterClosed = true
        if let adapter = run.adapter {
            let receipt = await adapter.retireRetainedAdapterWithoutDebuggerCommand()
            adapterClosed = receipt.didExit && receipt.didReap
            if !adapterClosed {
                run.cleanupDiagnostics.append("Native debugger cleanup: exited=\(receipt.didExit), reaped=\(receipt.didReap).")
            }
        }
        let targetClosed: Bool
        if let target = run.target { targetClosed = await target.killAndReap() } else { targetClosed = true }
        if !targetClosed, let target = run.target {
            run.cleanupDiagnostics.append("Native target exit and reap could not be confirmed: \(await target.cleanupDiagnostic()).")
        }
        guard targetClosed, adapterClosed else { return false }
        do {
            if let registration = run.registration {
                try await registry.retire(registration)
            } else if let token = run.token {
                if let target = run.target, let claim = run.claim {
                    let disposition = await target.retainedProcessDispositionForInfrastructure()
                    if disposition == .notLaunched {
                        try await registry.settleUnlaunchedProcess(claim, retainedProcess: target)
                    } else {
                        if !run.attemptedRegistration {
                            run.attemptedRegistration = true
                            do {
                                let registration = try await registry.registerSpawnedProcess(claim, retainedProcess: target)
                                run.registration = registration
                                try await registry.retire(registration)
                                return true
                            } catch { }
                        }
                        try await registry.retireUnresolvedSpawn(token, retainedProcess: target)
                    }
                } else { try await registry.cancelBeforeProcessLaunch(token) }
            }
            return true
        } catch {
            run.cleanupDiagnostics.append("Native ownership retirement failed: \(String(describing: error)).")
            return false
        }
    }

    private func ensureActive(_ run: Run) throws {
        try Task.checkCancellation()
        guard active === run, run.stopOutcome == nil else { throw CancellationError() }
    }

    private func requireUnchangedSource(_ image: NativeExecutionImage) throws {
        guard NativeExecutionFileStamp.capture(path: image.canonicalPath) == image.fileStamp else {
            throw NativeExecutionError.unavailable("The original executable changed; open and analyze the current file before another call.")
        }
    }

    private func launcherDiagnostic(at directory: URL) -> [String] {
        ["launcher", "stderr"].compactMap { name in
            guard let handle = try? FileHandle(forReadingFrom: directory.appendingPathComponent(name)) else { return nil }
            defer { try? handle.close() }
            guard let bytes = try? handle.read(upToCount: 2048), !bytes.isEmpty else { return nil }
            return String(decoding: bytes, as: UTF8.self)
        }
    }
}
