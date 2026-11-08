import Foundation
import MCP

/// Reusable outbound client. Policy belongs to its app-owned vendor adapter.
/// Cancellation or a deadline invalidates the complete connection generation.
/// Concurrent windows must therefore reauthorize new live handles after recovery.
public actor SDKExternalMCPClient: ExternalMCPClient {
    private var sdk: MCP.Client?
    private var transport: BoundedSubprocessTransport?
    private var current = MCPConnectionSnapshot()
    private var limits = MCPResourceLimits()
    private var catalog: [String: MCPToolDescriptor] = [:]
    private var catalogReady = false
    private var catalogEpoch: UInt64 = 0
    private var pending: Set<UUID> = []
    private var connecting = false
    private struct Discovery: Sendable {
        let id: UUID
        let generation: UUID
        let task: Task<[MCPToolDescriptor], any Error>
    }
    private var discovery: Discovery?
    private var discoveryWaiters: Set<UUID> = []
    private var terminalReasons: [UUID: MCPClientError] = [:]
    private var terminalOrder: [UUID] = []

    public init() {}

    deinit {
        // Actor tasks in the SDK/transport can retain their own actors. The app-facing
        // owner must release those cycles even when a window drops its last reference.
        let client = sdk
        let pipe = transport
        let discoveryTask = discovery?.task
        discoveryTask?.cancel()
        Task { [client, pipe] in
            await client?.disconnect()
            await pipe?.disconnect()
        }
    }

    public func snapshot() -> MCPConnectionSnapshot { current }

    public func connect(configuration: MCPConnectionConfiguration) async throws -> MCPConnectionSnapshot {
        guard !connecting, sdk == nil else { throw MCPClientError.connectionBusy }
        try configuration.validate()
        connecting = true
        defer { connecting = false }
        let generation = UUID()
        let client = MCP.Client(name: "MacScope", version: "1.0", configuration: .strict)
        let pipe = BoundedSubprocessTransport(configuration: configuration) { [weak self] error in
            await self?.invalidate(generation: generation, error: error)
        }
        sdk = client; transport = pipe; limits = configuration.limits
        catalog = [:]; catalogReady = false; catalogEpoch &+= 1
        current = MCPConnectionSnapshot(connectionID: generation, state: .connecting)
        await client.onNotification(ToolListChangedNotification.self) { [weak self] _ in
            guard let self else { return }
            await self.catalogChanged(generation: generation)
        }
        do {
            let result: Initialize.Result = try await withDeadline(generation: generation, client: client) {
                try await client.connect(transport: pipe)
            }
            try requireGeneration(generation, connected: false)
            guard Version.supported.contains(result.protocolVersion) else { throw MCPClientError.unsupportedProtocol }
            guard result.capabilities.tools != nil else { throw MCPClientError.capabilityMissing }
            current = MCPConnectionSnapshot(connectionID: generation, state: .connected,
                                            serverName: safeIdentity(result.serverInfo.name),
                                            serverVersion: safeIdentity(result.serverInfo.version),
                                            protocolVersion: result.protocolVersion)
            return current
        } catch {
            let code = terminalReasons[generation] ?? classify(error)
            await invalidate(generation: generation, error: code)
            throw code
        }
    }

    public func discoverTools() async throws -> [MCPToolDescriptor] {
        let (client, generation) = try connectedClient()
        let shared: Discovery
        if let active = discovery, active.generation == generation {
            shared = active
        } else {
            let id = UUID()
            let task = Task { [weak self] in
                guard let self else { throw MCPClientError.transportClosed }
                return try await self.performDiscovery(client: client, generation: generation)
            }
            shared = Discovery(id: id, generation: generation, task: task)
            discovery = shared
        }
        return try await awaitDiscovery(shared, client: client)
    }

    private func awaitDiscovery(_ shared: Discovery, client: MCP.Client) async throws -> [MCPToolDescriptor] {
        // Coalescing bounds wire work, but each suspended caller also consumes memory.
        guard discoveryWaiters.count < limits.maximumPendingRequests else { throw MCPClientError.tooManyRequests }
        let waiter = UUID()
        discoveryWaiters.insert(waiter)
        defer {
            discoveryWaiters.remove(waiter)
            if discovery?.id == shared.id { discovery = nil }
        }
        do {
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                let result = try await shared.task.value
                try Task.checkCancellation()
                try requireGeneration(shared.generation)
                guard catalogReady, result.allSatisfy({ catalog[$0.name] == $0 }), result.count == catalog.count
                else { throw MCPClientError.staleConnection }
                return result
            } onCancel: {
                Task { [weak self] in
                    await self?.cancelGeneration(shared.generation, client: client, requestID: nil, error: .cancelled)
                }
            }
        } catch {
            if error is CancellationError {
                await cancelGeneration(shared.generation, client: client, requestID: nil, error: .cancelled)
            }
            throw terminalReasons[shared.generation] ?? classify(error)
        }
    }

    private func performDiscovery(client: MCP.Client, generation: UUID) async throws -> [MCPToolDescriptor] {
        try requireGeneration(generation)
        let previouslyReady = catalogReady
        var successful = false
        defer {
            if !successful, current.connectionID == generation {
                catalog = [:]; catalogReady = false; catalogEpoch &+= 1
                updateRevision(current.toolCatalogRevision &+ 1)
            }
        }
        let token = try reserveRequest()
        defer { pending.remove(token) }
        let startedEpoch = catalogEpoch
        var found: [String: MCPToolDescriptor] = [:]
        var seenCursors: Set<String> = []
        var cursor: String?
        for page in 0..<limits.maximumToolPages {
            let listRequest: Request<ListTools>
            if let cursor {
                listRequest = ListTools.request(.init(cursor: cursor))
            } else {
                listRequest = ListTools.request(.init())
            }
            let result: ListTools.Result = try await request(
                listRequest, client: client, generation: generation)
            try requireGeneration(generation)
            guard startedEpoch == catalogEpoch else { throw MCPClientError.staleConnection }
            for tool in result.tools {
                guard validToolName(tool.name), found[tool.name] == nil,
                      tool.inputSchema.objectValue != nil else { throw MCPClientError.protocolFailure }
                let descriptor = MCPToolDescriptor(
                    name: tool.name, inputSchema: tool.inputSchema, outputSchema: tool.outputSchema,
                    schemaDigest: try MCPBoundaryValidation.schemaDigest(
                        input: tool.inputSchema, output: tool.outputSchema, limits: limits))
                found[tool.name] = descriptor
                guard found.count <= limits.maximumTools else { throw MCPClientError.toolCatalogLimit }
            }
            cursor = result.nextCursor
            if let cursor {
                guard cursor.utf8.count <= 4_096, seenCursors.insert(cursor).inserted
                else { throw MCPClientError.repeatedCursor }
                guard page + 1 < limits.maximumToolPages else { throw MCPClientError.toolCatalogLimit }
            } else {
                let changed = !previouslyReady || found != catalog
                catalog = found; catalogReady = true
                if changed { catalogEpoch &+= 1; updateRevision(current.toolCatalogRevision &+ 1) }
                successful = true
                return found.values.sorted { $0.name < $1.name }
            }
        }
        throw MCPClientError.toolCatalogLimit
    }

    public func invoke(tool: String, arguments: MCPJSONValue) async throws -> MCPToolOutcome {
        let (client, generation) = try connectedClient()
        guard catalogReady, let acceptedDescriptor = catalog[tool] else { throw MCPClientError.unknownTool }
        let acceptedRevision = current.toolCatalogRevision
        // Ordinary refresh is shared by windows; it does not erase an accepted catalog.
        // A new call waits for its result rather than racing the advertised schema.
        if let active = discovery, active.generation == generation {
            _ = try await awaitDiscovery(active, client: client)
        }
        try requireGeneration(generation)
        // The caller authorized against the entry catalog. A changed refresh must
        // return to that policy boundary before any old arguments can be dispatched.
        guard catalogReady, catalog[tool] == acceptedDescriptor,
              current.toolCatalogRevision == acceptedRevision else { throw MCPClientError.staleConnection }
        guard let object = arguments.objectValue else { throw MCPClientError.invalidArguments }
        _ = try MCPBoundaryValidation.canonicalData(arguments, limits: limits)
        let token = try reserveRequest()
        defer { pending.remove(token) }
        let epoch = catalogEpoch
        let result: CallTool.Result = try await request(
            CallTool.request(.init(name: tool, arguments: object)), client: client, generation: generation)
        try requireGeneration(generation)
        guard catalogReady, catalogEpoch == epoch else { throw MCPClientError.staleConnection }
        if let structured = result.structuredContent { try MCPBoundaryValidation.validate(structured, limits: limits) }
        var texts: [String] = []
        var totalBytes = 0
        for item in result.content {
            switch item {
            case .text(let text, _, _):
                totalBytes += text.utf8.count
                guard totalBytes <= limits.maximumMessageBytes, texts.count < 64
                else { throw MCPClientError.responseTooLarge }
                texts.append(text)
            default: throw MCPClientError.unsupportedContent
            }
        }
        return MCPToolOutcome(connectionID: generation, toolName: tool,
                              structuredContent: result.structuredContent, textContent: texts,
                              isError: result.isError == true)
    }

    public func disconnect() async {
        guard let generation = current.connectionID else { return }
        await invalidate(generation: generation, error: nil)
    }

    private func request<M: MCP.Method>(_ request: Request<M>, client: MCP.Client,
                                    generation: UUID) async throws -> M.Result {
        do {
            try Task.checkCancellation()
            let context: RequestContext<M.Result> = try await client.send(request)
            let result = try await withDeadline(generation: generation, client: client, requestID: context.requestID) {
                try await context.value
            }
            try requireGeneration(generation)
            return result
        } catch {
            if let reason = terminalReasons[generation] { throw reason }
            if error is CancellationError { throw MCPClientError.cancelled }
            if let code = error as? MCPClientError { throw code }
            // The diagnostic never carries SDK error text or external content.
            throw MCPClientError.serverError
        }
    }

    private func withDeadline<Result: Sendable>(generation: UUID, client: MCP.Client,
                                              requestID: ID? = nil,
                                              operation: @escaping @Sendable () async throws -> Result) async throws -> Result {
        let duration = limits.requestTimeout
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withThrowingTaskGroup(of: Result.self) { group in
                group.addTask { try await operation() }
                group.addTask { [weak self] in
                    try await Task.sleep(for: .seconds(duration))
                    await self?.cancelGeneration(generation, client: client, requestID: requestID, error: .deadlineExceeded)
                    throw MCPClientError.deadlineExceeded
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else { throw MCPClientError.protocolFailure }
                return result
            }
        } onCancel: {
            Task { [weak self] in
                await self?.cancelGeneration(generation, client: client, requestID: requestID, error: .cancelled)
            }
        }
    }

    private func cancelGeneration(_ generation: UUID, client: MCP.Client, requestID: ID?, error: MCPClientError) async {
        guard current.connectionID == generation else { return }
        if let requestID {
            // Advisory notification is bounded by the same transport teardown; no replay follows.
            Task { try? await client.cancelRequest(requestID, reason: error.rawValue) }
        }
        await invalidate(generation: generation, error: error)
    }

    private func invalidate(generation: UUID, error: MCPClientError?) async {
        guard current.connectionID == generation else { return }
        let client = sdk, pipe = transport
        let activeDiscovery = discovery
        discovery = nil
        discoveryWaiters.removeAll()
        activeDiscovery?.task.cancel()
        terminalReasons[generation] = error ?? .transportClosed
        terminalOrder.append(generation)
        if terminalOrder.count > 16 { terminalReasons.removeValue(forKey: terminalOrder.removeFirst()) }
        sdk = nil; transport = nil; catalog = [:]; catalogReady = false; catalogEpoch &+= 1
        let state: MCPConnectionState
        switch error {
        case nil: state = .disconnected
        case .unsupportedProtocol: state = .unsupportedVersion
        case .permissionDenied, .untrustedExecutable: state = .permissionDenied
        case .protocolFailure, .malformedMessage: state = .protocolError
        default: state = .degraded
        }
        current = MCPConnectionSnapshot(state: state, diagnosticCode: error?.rawValue)
        // Client disconnect fails SDK continuations, including other windows' outstanding reads.
        await client?.disconnect()
        await pipe?.disconnect()
    }

    private func catalogChanged(generation: UUID) {
        guard current.connectionID == generation else { return }
        catalog = [:]; catalogReady = false; catalogEpoch &+= 1
        updateRevision(current.toolCatalogRevision &+ 1)
    }

    private func updateRevision(_ revision: UInt64) {
        current = MCPConnectionSnapshot(connectionID: current.connectionID, state: current.state,
                                        serverName: current.serverName, serverVersion: current.serverVersion,
                                        protocolVersion: current.protocolVersion, toolCatalogRevision: revision,
                                        diagnosticCode: current.diagnosticCode)
    }

    private func reserveRequest() throws -> UUID {
        guard pending.count < limits.maximumPendingRequests else { throw MCPClientError.tooManyRequests }
        let id = UUID(); pending.insert(id); return id
    }

    private func connectedClient() throws -> (MCP.Client, UUID) {
        guard current.state == .connected, let sdk, let id = current.connectionID
        else { throw MCPClientError.notConnected }
        return (sdk, id)
    }

    private func requireGeneration(_ id: UUID, connected: Bool = true) throws {
        guard current.connectionID == id, sdk != nil, !connected || current.state == .connected
        else { throw MCPClientError.staleConnection }
    }

    private func classify(_ error: any Error) -> MCPClientError {
        if let error = error as? MCPClientError { return error }
        return error is CancellationError ? .cancelled : .protocolFailure
    }

    private func validToolName(_ name: String) -> Bool {
        !name.isEmpty && name.utf8.count <= 128 && name.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45, 46, 95].contains($0)
        }
    }

    private func safeIdentity(_ value: String) -> String {
        String(value.unicodeScalars.filter { (32...126).contains($0.value) }.prefix(128))
    }
}
