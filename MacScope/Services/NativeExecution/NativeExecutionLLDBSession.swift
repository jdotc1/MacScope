import Foundation

enum NativeExecutionLLDBConstruction: Sendable {
    case ready(NativeExecutionLLDBSession)
    case unresolved(PersistentLLDBCLIAdapter)
}

/// Private coordinator for one owned native-call transaction. It never shares an ordinary
/// debugger session and never admits commands from a UI or caller-supplied expression.
actor NativeExecutionLLDBSession {
    private enum Phase { case targetless, attached, atEntry, ready, callConsumed, collected }
    private let adapter: PersistentLLDBCLIAdapter
    private let epoch: DebuggerSessionEpoch
    private let anchor: DebuggerLocalProcessInstanceKey
    private let permit: NativeExecutionOwnedTargetPermit
    private let request: NativeFunctionCallRequest
    private let token: String
    private var phase: Phase = .targetless
    private var requestSequence: UInt64 = 0
    private var packetSequence = 0
    private var stopID: UInt32 = 0
    private var runtimeFunctionAddress: UInt64?

    private init(adapter: PersistentLLDBCLIAdapter, epoch: DebuggerSessionEpoch,
                 permit: NativeExecutionOwnedTargetPermit, request: NativeFunctionCallRequest) {
        self.adapter = adapter
        self.epoch = epoch
        self.permit = permit
        self.anchor = permit.anchor
        self.request = request
        token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }

    static func make(toolchain: DebuggerLLDBToolchain, registry: DebuggerOwnedInfrastructureRegistry,
                     jobDirectory: URL, permit: NativeExecutionOwnedTargetPermit,
                     request: NativeFunctionCallRequest) async throws -> NativeExecutionLLDBConstruction {
        guard permit.path == request.image.canonicalPath, await permit.isCurrent() else {
            throw NativeExecutionError.unavailable("The retained native target cannot authorize this debugger session.")
        }
        let plan = try await MainActor.run {
            try PersistentLLDBTargetlessTransportPlan.make(toolchain: toolchain,
                environment: ProcessInfo.processInfo.environment, fallbackWorkingDirectory: jobDirectory.path,
                timeout: .seconds(8))
        }
        let factory = PersistentLLDBTargetlessTransportFactory(ownedInfrastructureRegistry: registry,
            localProcessEvidenceProvider: DarwinDebuggerLocalProcessEvidenceProvider())
        let epoch = DebuggerSessionEpoch()
        let outcome = try await factory.make(plan: plan, epoch: epoch)
        switch outcome {
        case .acquired(let transport):
            return .ready(NativeExecutionLLDBSession(adapter: transport.adapter, epoch: epoch, permit: permit, request: request))
        case .unresolved(_, let adapter): return .unresolved(adapter)
        }
    }

    func retainedAdapter() -> PersistentLLDBCLIAdapter { adapter }

    func prepare(programSource: Data) async throws -> UInt64 {
        guard phase == .targetless else { throw NativeExecutionError.invalidRequest("Native session preparation was already consumed.") }
        // Match the ordinary backend's safe formatting: no libdispatch extended-thread queries.
        let settings = [
            "settings set use-color false",
            "settings set target.input-path /dev/null",
            "settings set thread-stop-format \"thread #${thread.index}: tid = ${thread.id%tid}{, stop reason = ${thread.stop-reason}}\\n\"",
            "settings set thread-format \"thread #${thread.index}: tid = ${thread.id%tid}{, ${frame.pc}}{ ${module.file.basename}`${function.name}}{, name = '${thread.name}'}\"",
        ]
        let program = try NativeLLDBCallProgram(source: programSource)
        for command in settings + program.installationCommands {
            let semantic = try await send(command, operation: .launch)
            guard semantic.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw NativeExecutionError.invalidResponse("The native execution program emitted unexpected installation output.")
            }
        }
        let upload = try NativeLLDBCallProgram.requestCommands(request, anchor: anchor, token: token)
        for (index, command) in upload.enumerated() {
            let receipt = try await packet(command, operation: .launch, expectedPhase: index == 0 ? "begin" : "append")
            if index > 0, receipt.index != index - 1 { throw NativeExecutionError.invalidResponse("Native request chunks were reordered.") }
        }
        guard await permit.isCurrent() else { throw NativeExecutionError.unavailable("The native target changed before attachment.") }
        let attached = try await packet(NativeLLDBCallProgram.command(.attach, token: token), operation: .launch, expectedPhase: "attach")
        try acceptStop(attached)
        phase = .attached
        let entry = try await packet(NativeLLDBCallProgram.command(.entry, token: token), operation: .continue, expectedPhase: "entry")
        try acceptStop(entry)
        guard let address = entry.function.flatMap(UInt64.init), address > 0 else {
            throw NativeExecutionError.invalidResponse("Native function mapping is unavailable.")
        }
        runtimeFunctionAddress = address
        phase = .atEntry
        let memory = try await packet(NativeLLDBCallProgram.command(.memory, token: token), operation: .writeMemory, expectedPhase: "memory")
        try acceptStop(memory)
        guard let count = memory.regions, (0...16).contains(count) else {
            throw NativeExecutionError.invalidResponse("Native memory observation count is invalid.")
        }
        phase = .ready
        return address
    }

    func invokeAndCollect() async throws -> NativeFunctionCallResult {
        guard phase == .ready, let runtimeFunctionAddress else {
            throw NativeExecutionError.invalidRequest("Native call is not ready or was already invoked.")
        }
        phase = .callConsumed
        guard await permit.isCurrent() else { throw NativeExecutionError.unavailable("The native target changed before invocation.") }
        let called = try await packet(NativeLLDBCallProgram.command(.call, token: token), operation: .evaluateExpression,
            expectedPhase: "call", timeout: .seconds(request.timeoutSeconds + 1))
        guard called.pid == anchor.processID, let count = called.pages, (1...11).contains(count) else {
            throw NativeExecutionError.invalidResponse("Native result page count or process changed.")
        }
        var encoded = ""
        for index in 0..<count {
            let page = try await packet(NativeLLDBCallProgram.command(.page, token: token, page: index),
                operation: .pollProcessStatus, expectedPhase: "page")
            guard page.index == index, page.count == count, let data = page.data,
                  data.utf8.count <= 32_768, encoded.utf8.count + data.utf8.count <= 349_528 else {
                throw NativeExecutionError.invalidResponse("Native result pages were reordered or exceeded capacity.")
            }
            encoded += data
        }
        guard let raw = Data(base64Encoded: encoded), raw.base64EncodedString() == encoded else {
            throw NativeExecutionError.invalidResponse("Native result has invalid byte framing.")
        }
        let result = try NativeLLDBCallDecoder.result(raw, request: request, runtimeFunctionAddress: runtimeFunctionAddress)
        phase = .collected
        return result
    }

    func destroyOwnedTarget() async throws {
        guard phase != .targetless else { return }
        let command = NativeLLDBCallProgram.command(.close, token: token)
        let semantic = try await send(command, operation: .terminate, timeout: .seconds(1), allowExitedProcess: true)
        packetSequence += 1
        _ = try NativeLLDBCallDecoder.phase(semantic, requestID: request.id, token: token,
            sequence: packetSequence, expectedPhase: "close")
    }

    private func acceptStop(_ receipt: NativeLLDBPhaseReceipt) throws {
        guard receipt.pid == anchor.processID, let stop = receipt.stop, stop > 0 else {
            throw NativeExecutionError.invalidResponse("Native execution process or stop identity changed.")
        }
        stopID = stop
    }

    private func packet(_ command: String, operation: DebuggerOperation, expectedPhase: String,
                        timeout: Duration = .seconds(8)) async throws -> NativeLLDBPhaseReceipt {
        let semantic = try await send(command, operation: operation, timeout: timeout)
        packetSequence += 1
        return try NativeLLDBCallDecoder.phase(semantic, requestID: request.id, token: token,
            sequence: packetSequence, expectedPhase: expectedPhase)
    }

    private func send(_ command: String, operation: DebuggerOperation, timeout: Duration = .seconds(8), allowExitedProcess: Bool = false) async throws -> String {
        try Task.checkCancellation()
        requestSequence += 1
        let coordinate = DebuggerSessionCoordinate(epoch: epoch, lifecycleRevision: .initial)
        let stop = operation.requiresStopCoordinate
            ? DebuggerStopCoordinate(session: coordinate, stopRevision: DebuggerStopRevision(rawValue: UInt64(stopID))) : nil
        let context = DebuggerRequestContext(id: DebuggerRequestID(epoch: epoch, sequence: requestSequence),
            operation: operation, expectedSession: coordinate, requiredStop: stop)
        // This coordinator has already selected the one fixed physical command from its typed
        // phase and owns the launched child's immutable kernel identity. There is no external
        // attach selection or ordinary-debugger state to borrow here.
        let physical = try PersistentLLDBCLIRequest(context: context, semanticCommands: [command],
            observedPIDRequirement: phase == .targetless || allowExitedProcess ? .optional : .required, timeout: timeout)
        let response: PersistentLLDBCLIResponse
        do {
            response = try await adapter.executeCoordinatorSelected(physical)
        } catch let failure as PersistentLLDBCLIAdapterFailure {
            throw NativeExecutionError.invalidResponse("Native debugger \(operation.displayLabel) failed at exchange \(requestSequence): \(failure.code.rawValue) (\(String(describing: failure.transcriptDiagnosticCode))).")
        }
        guard response.requestID == context.id, response.generation == 1,
              response.transcript.semanticCommandsSucceeded,
              response.transcript.semanticCommandTranscripts.count == 1,
              phase == .targetless || allowExitedProcess || response.transcript.observedProcessID == anchor.processID else {
            throw NativeExecutionError.invalidResponse("Native transport response does not match the owned session.")
        }
        return response.transcript.semanticCommandTranscripts[0]
    }
}
