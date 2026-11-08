import Darwin
import Foundation

/// Reserve a bounded receipt for a batch before its mutation is admitted.
enum MCPBatchReceiptBudget {
    static let commands: Set<String> = ["set-local-labels", "clear-segment-overrides", "set-operand-formats", "set-types", "rename-registers", "clear-register-names", "set-stack-locals", "set-tags", "set-colors", "add-xrefs", "suppress-xrefs", "add-bookmarks", "remove-bookmarks", "set-signatures", "rename-segments", "rebase-segments", "make-arrays", "make-strings", "make-alignments", "set-data", "set-procedures", "set-undefined"]
    static let refusal = "Request ID leaves no room for a batch receipt; use a shorter ID."
    static func admits(idBytes: Int, maximumBytes: Int) -> Bool {
        maximumBytes >= 384 && idBytes <= maximumBytes - 384
    }

    // Called before dispatch. Keep the original ID and a truthful message, or fail
    // the connection if even the shortest correlated refusal cannot fit.
    static func refusalFrame(id: Phase2ProductionJSONValue, maximumBytes: Int) throws -> Data {
        let typed = MCPServerTerminal.receiptID.frame(id: id, code: -32602, message: refusal)
        if MCPFrameAdmission.fits(typed, maximumBytes: maximumBytes) { return typed }
        for message in [refusal, "Batch not run; shorten ID.", "Not run"] {
            let frame = Phase2ProductionJSONValue.object([
                "jsonrpc": .string("2.0"), "id": id,
                "error": .object(["code": .integer(-32602), "message": .string(message)])
            ]).canonicalJSONBytes()
            if MCPFrameAdmission.fits(frame, maximumBytes: maximumBytes) { return frame }
        }
        throw MCPFrameAdmission.Failure.unrepresentable
    }
}

enum HeadlessJSONError: LocalizedError {
    case invalid

    var errorDescription: String? { "Invalid bounded JSON." }
}

enum MCPServerTerminal: Sendable {
    case deadline(limitNanoseconds: UInt64, usedNanoseconds: UInt64?)
    case output(limit: Int, used: Int)
    case frame(limit: Int, payloadBytes: Int)
    case encoding
    case inFlight(limit: Int, used: Int)
    case invalidParams(field: String?, expected: String?)
    case receiptID

    static func milliseconds(_ nanoseconds: UInt64) -> Int64 {
        let whole = nanoseconds / 1_000_000
        let rounded = whole + (nanoseconds % 1_000_000 == 0 ? 0 : 1)
        return Int64(clamping: rounded)
    }

    var refusal: MCPToolRefusal {
        switch self {
        case let .deadline(limit, used):
            return MCPToolRefusal(code: .budgetExceeded, detail: "Deadline exceeded.",
                budget: .init(unit: .wallMillis, limit: Self.milliseconds(limit)),
                used: used.map(Self.milliseconds), narrowing: [])
        case let .output(limit, used):
            return MCPToolRefusal(code: .budgetExceeded, detail: "Output limit exceeded.",
                budget: .init(unit: .bytes, limit: Int64(clamping: limit)),
                used: Int64(clamping: used), narrowing: [])
        case let .frame(limit, payloadBytes):
            let count = Int64(clamping: payloadBytes)
            let used = count == Int64.max ? count : count + 1
            return MCPToolRefusal(code: .budgetExceeded, detail: "Frame limit exceeded.",
                budget: .init(unit: .bytes, limit: Int64(clamping: limit)),
                used: used, narrowing: [])
        case let .inFlight(limit, used):
            return MCPToolRefusal(code: .budgetExceeded,
                detail: "In-flight limit exceeded.", retryable: true,
                budget: .init(unit: .requests, limit: Int64(clamping: limit)),
                used: Int64(clamping: used), narrowing: [])
        case let .invalidParams(field, expected):
            return MCPToolRefusal(code: .malformedInput, detail: "Invalid params",
                field: field, expected: expected)
        case .receiptID:
            return MCPToolRefusal(code: .outOfBounds, detail: "Request ID is too long.",
                field: "id", expected: "shorter ID")
        case .encoding:
            return MCPToolRefusal(code: .preconditionFailed, detail: "Response encoding failed.")
        }
    }

    var scriptValue: ScriptValue { refusal.value }

    // Match refusal.value for every field these internal constructors can set.
    // Exact integers are written as decimal strings, never through Double.
    var phaseValue: Phase2ProductionJSONValue {
        let value = refusal
        var fields: [String: Phase2ProductionJSONValue] = [
            "code": .string(value.code.rawValue), "detail": .string(value.detail),
            "retryable": .bool(value.retryable)
        ]
        if let field = value.field { fields["field"] = .string(field) }
        if let expected = value.expected { fields["expected"] = .string(expected) }
        if let allowed = value.allowed { fields["allowed"] = .array(allowed.map { .string($0) }) }
        if let minimum = value.minimum { fields["minimum"] = .number(String(minimum)) }
        if let maximum = value.maximum { fields["maximum"] = .number(String(maximum)) }
        if let budget = value.budget {
            fields["budget"] = .object([
                "unit": .string(budget.unit.rawValue), "limit": .number(String(budget.limit))
            ])
            fields["used"] = value.used.map { .number(String($0)) } ?? .null
        }
        if value.narrowing != nil { fields["narrowing"] = .array([]) }
        return .object(["error": .string("refused"), "refusal": .object(fields)])
    }

    func frame(id: Phase2ProductionJSONValue, code: Int,
               message: String) -> Data {
        Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": id,
            "error": .object([
                "code": .integer(code), "message": .string(message), "data": phaseValue
            ])
        ]).canonicalJSONBytes()
    }
}

/// Produces payload bytes only; the transport must append exactly one LF.
enum MCPFrameAdmission {
    enum Failure: Error { case unrepresentable }

    static func fits(_ payload: Data, maximumBytes: Int) -> Bool {
        maximumBytes > 0 && !payload.isEmpty && payload.count < maximumBytes
            && !payload.contains(0x0a) && !payload.contains(0x0d)
    }

    private static func receiptResultWithoutTyping(
        _ value: Phase2ProductionJSONValue?, receiptText: String?, maximumBytes: Int
    ) -> Phase2ProductionJSONValue? {
        guard let receiptText, let fields = value?.objectValue,
              Set(fields.keys) == Set(["content", "isError"]),
              fields["isError"] == .bool(true),
              case .array(let content)? = fields["content"], content.count == 2,
              content[0] == .object(["type": .string("text"), "text": .string(receiptText)]),
              let second = content[1].objectValue,
              Set(second.keys) == Set(["type", "text"]), second["type"] == .string("text"),
              let text = second["text"]?.stringValue else { return nil }
        let recognized: Bool
        if text == MCPServerTerminal.encoding.refusal.text {
            recognized = true
        } else if let parsed = try? Phase2StrictJSONParser().parse(Data(text.utf8), limits: .providerEnvelope),
                  case .number(let lexeme)? = parsed.objectValue?["refusal"]?.objectValue?["used"],
                  let used = Int(lexeme), used >= 0 {
            recognized = text == MCPServerTerminal.output(limit: maximumBytes / 2, used: used).refusal.text
        } else {
            recognized = false
        }
        guard recognized else { return nil }
        return .object(["content": .array([content[0]]), "isError": .bool(true)])
    }

    static func response(_ data: Data, id: Phase2ProductionJSONValue,
                         maximumBytes: Int, failureMessage: String = "Response exceeds limit",
                         compactMessage: String = "", receiptResultText: String? = nil) throws -> Data {
        let decoded = try? Phase2StrictJSONParser().parse(data, limits: .init(
            maximumBytes: max(1, data.count), maximumDepth: 64,
            maximumTokens: max(1, data.count), maximumMembersAndElements: max(1, data.count))).objectValue
        let hasResult = decoded?.keys.contains("result") == true
        let hasError = decoded?.keys.contains("error") == true
        let validResponseID: Bool
        switch decoded?["id"] {
        case .some(.null), .some(.string), .some(.number): validResponseID = true
        default: validResponseID = false
        }
        let errorFields = decoded?["error"]?.objectValue
        let validError: Bool
        if case .number(let code)? = errorFields?["code"], Int(code) != nil,
           case .string? = errorFields?["message"] { validError = true } else { validError = false }
        let valid = decoded?["jsonrpc"] == .string("2.0") && validResponseID
            && decoded?["method"] == nil && hasResult != hasError && (!hasError || validError)
        let codeValue = errorFields?["code"]
        let unsafeTerminal = !compactMessage.isEmpty && (codeValue == .integer(-32800)
            || codeValue == .integer(-32001)
            || (codeValue == .integer(-32603) && errorFields?["message"] == .string("Response exceeds limit")))
        var restoredBytes: Data?
        var restoredFields: [String: Phase2ProductionJSONValue]?
        if valid, var fields = decoded {
            fields["id"] = id
            let encoded = Phase2ProductionJSONValue.object(fields).canonicalJSONBytes()
            restoredBytes = encoded
            restoredFields = fields
            if !unsafeTerminal, fits(encoded, maximumBytes: maximumBytes) { return encoded }
        }
        if valid, hasResult, var fields = restoredFields,
           let bareResult = receiptResultWithoutTyping(fields["result"],
                receiptText: receiptResultText, maximumBytes: maximumBytes) {
            fields["result"] = bareResult
            let bare = Phase2ProductionJSONValue.object(fields).canonicalJSONBytes()
            restoredBytes = bare
            restoredFields = fields
            if fits(bare, maximumBytes: maximumBytes) { return bare }
        }
        // Typing is strictly additive: an eligible typed terminal that does not fit first
        // falls back to the same reply without error.data, which is today's reply.
        if valid, hasError, !unsafeTerminal, var fields = restoredFields, var typedError = errorFields,
           typedError["data"] != nil,
           codeValue == .integer(-32001) || codeValue == .integer(-32603)
            || codeValue == .integer(-32000) || codeValue == .integer(-32602) {
            typedError["data"] = nil
            fields["error"] = .object(typedError)
            let untyped = Phase2ProductionJSONValue.object(fields).canonicalJSONBytes()
            if fits(untyped, maximumBytes: maximumBytes) { return untyped }
        }
        let code: Phase2ProductionJSONValue = valid && hasError && compactMessage.isEmpty
            ? errorFields!["code"]! : .integer(-32603)
        let fullMessage = !valid && compactMessage.isEmpty ? "Invalid response" : failureMessage
        let typedData: Phase2ProductionJSONValue?
        if unsafeTerminal, codeValue != .integer(-32800) {
            typedData = errorFields?["data"]
        } else if valid, hasResult, let restoredBytes {
            typedData = MCPServerTerminal.frame(limit: maximumBytes,
                payloadBytes: restoredBytes.count).phaseValue
        } else if !valid {
            typedData = MCPServerTerminal.encoding.phaseValue
        } else {
            typedData = nil
        }
        if let typedData, code == .integer(-32603) || code == .integer(-32001) {
            let typed = Phase2ProductionJSONValue.object([
                "jsonrpc": .string("2.0"), "id": id,
                "error": .object([
                    "code": code, "message": .string(fullMessage), "data": typedData
                ])
            ]).canonicalJSONBytes()
            if fits(typed, maximumBytes: maximumBytes) { return typed }
        }
        for message in [fullMessage, compactMessage] {
            let fallback = Phase2ProductionJSONValue.object([
                "jsonrpc": .string("2.0"), "id": id,
                "error": .object(["code": code, "message": .string(message)])
            ]).canonicalJSONBytes()
            if fits(fallback, maximumBytes: maximumBytes) { return fallback }
        }
        throw Failure.unrepresentable
    }
}

/// Admission and failure share a linearization point; already-admitted work may finish.
final class MCPConnectionFence: @unchecked Sendable {
    private let lock = NSLock()
    private var failed = false
    private let onFailure: @Sendable () -> Void

    init(onFailure: @escaping @Sendable () -> Void = {}) { self.onFailure = onFailure }

    var isFailed: Bool {
        lock.lock(); defer { lock.unlock() }
        return failed
    }

    func fail() {
        lock.lock()
        let notify = !failed
        failed = true
        lock.unlock()
        if notify { onFailure() }
    }

    func admit<T>(_ body: () throws -> T) throws -> T {
        lock.lock()
        let permitted = !failed
        lock.unlock()
        guard permitted else { throw MCPFrameAdmission.Failure.unrepresentable }
        return try body()
    }
}

/// A returned operation and a durable commit are distinct outcomes.
final class MCPMutationOutcome: @unchecked Sendable {
    enum State: Equatable, Sendable { case notStarted, unknown, returned, committed, rolledBack }
    private let lock = NSLock()
    private var state: State = .notStarted
    private var receipt: ScriptingBatchHistoryFailure.Receipt?

    var snapshot: State { lock.lock(); defer { lock.unlock() }; return state }
    var batchReceipt: ScriptingBatchHistoryFailure.Receipt? { lock.lock(); defer { lock.unlock() }; return receipt }
    func recordBatchReceipt(_ receipt: ScriptingBatchHistoryFailure.Receipt) { lock.lock(); self.receipt = receipt; lock.unlock() }
    func started() { lock.lock(); if state == .notStarted { state = .unknown }; lock.unlock() }
    func returned() { lock.lock(); if state != .committed { state = .returned }; lock.unlock() }
    func committed() { lock.lock(); state = .committed; lock.unlock() }
    func rolledBack() { lock.lock(); state = .rolledBack; receipt = nil; lock.unlock() }
}

private final class MCPCommitSpan: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true
    var isActive: Bool { lock.lock(); defer { lock.unlock() }; return active }
    func finish() { lock.lock(); active = false; lock.unlock() }
}

enum MCPExecutionFence {
    @TaskLocal static var connection: MCPConnectionFence?
    @TaskLocal static var outcome: MCPMutationOutcome?
    @TaskLocal private static var span: MCPCommitSpan?

    static func commit<T>(_ body: () throws -> T) throws -> T {
        if span?.isActive == true { return try body() }
        func invoke() throws -> T {
            outcome?.started()
            let current = MCPCommitSpan()
            defer { current.finish() }
            let result = try $span.withValue(current, operation: body)
            outcome?.returned()
            return result
        }
        if let connection { return try connection.admit { try invoke() } }
        return try invoke()
    }
}

struct MCPPostMutationReportFailure: Error {
    let result: ScriptValue
    let underlying: any Error
}

/// Owns framing output independently of the workspace actor. Each complete NDJSON
/// line is written in one serialized span, even when requests complete out of order.
private actor MCPResponseWriter {
    let output: FileHandle
    private let fence: MCPConnectionFence
    private let maximumBytes: Int
    init(output: FileHandle, maximumBytes: Int, fence: MCPConnectionFence) {
        self.output = output
        self.maximumBytes = maximumBytes
        self.fence = fence
    }
    func write(_ data: Data) throws {
        do {
            guard MCPFrameAdmission.fits(data, maximumBytes: maximumBytes) else {
                throw MCPFrameAdmission.Failure.unrepresentable
            }
            try fence.admit { try HeadlessProtocolIO.writeLine(data, to: output) }
        } catch {
            fence.fail()
            throw error
        }
    }
}

/// Session-scoped admission and cancellation never require MainActor. Cancelled
/// reads retain a bounded retirement slot until their owned task actually returns;
/// a reused ID cannot consume a late completion from the previous invocation.
actor MCPRequestSession {
    typealias Execute = @Sendable (Data) async -> Data?
    private struct Entry: Sendable {
        let token: UUID
        let request: Data
        let responseID: Phase2ProductionJSONValue?
        let mutation: Bool
        let outcome: MCPMutationOutcome
        var task: Task<Void, Never>?
        var deadline: Task<Void, Never>?
        var progress: Task<Void, Never>?
        var drainingTerminal = false
        var terminal = false
        var cancellation: (code: Int, message: String)?
    }
    private let configuration: MCPServer.Configuration
    private let fence: MCPConnectionFence
    private let mutatingCommands: Set<String>
    private let execute: Execute
    private let output: @Sendable (Data) async throws -> Void
    private let progressSource: MCPStartupStatus?
    private let progressIntervalNanoseconds: UInt64
    private var entries: [String: Entry] = [:]
    private var mutationQueue: [String] = []
    private var activeMutation: String?
    private var accepting = true
    private var outputFailed = false
    private var pendingWrites = 0
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []

    init(configuration: MCPServer.Configuration, mutatingCommands: Set<String>,
         execute: @escaping Execute, output: @escaping @Sendable (Data) async throws -> Void,
         fence: MCPConnectionFence = MCPConnectionFence(),
         progressSource: MCPStartupStatus? = nil,
         progressIntervalNanoseconds: UInt64 = 250_000_000) {
        self.configuration = configuration
        self.fence = fence
        self.mutatingCommands = mutatingCommands
        self.execute = execute
        self.output = output
        self.progressSource = progressSource
        self.progressIntervalNanoseconds = max(1, progressIntervalNanoseconds)
    }

    var inFlightCount: Int { entries.count }
    var isAcceptingRequests: Bool { accepting && !fence.isFailed }
    var pendingTerminalWriteCount: Int { pendingWrites }
    var isAwaitingInputDrain: Bool { !drainWaiters.isEmpty }

    func receiveOversized() async { await emitError(id: nil, code: -32700, message: "Parse error") }

    func receive(_ data: Data) async {
        guard accepting, !fence.isFailed,
              !data.allSatisfy({ [0x20, 0x09, 0x0A, 0x0D].contains($0) }) else { return }
        let value: Phase2ProductionJSONValue
        do {
            value = try Phase2StrictJSONParser().parse(data, limits: .init(
                maximumBytes: configuration.maximumInputBytes, maximumDepth: 16,
                maximumTokens: 100_000, maximumMembersAndElements: 50_000))
        } catch { await receiveOversized(); return }
        guard var fields = value.objectValue, fields["jsonrpc"] == .string("2.0"),
              let method = fields["method"]?.stringValue, !method.isEmpty,
              method.utf8.count <= 256,
              !method.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              fields["id"] == nil || Self.key(fields["id"]) != nil else {
            await emitError(id: nil, code: -32600, message: "Invalid Request")
            return
        }
        let responseID = fields["id"]
        if method == "tools/call", let command = fields["params"]?.objectValue?["name"]?.stringValue,
           MCPBatchReceiptBudget.commands.contains(command),
           !MCPBatchReceiptBudget.admits(idBytes: responseID?.canonicalJSONBytes().count ?? 4,
                                         maximumBytes: configuration.maximumOutputBytes) {
            if let responseID {
                do {
                    let frame = try MCPBatchReceiptBudget.refusalFrame(id: responseID, maximumBytes: configuration.maximumOutputBytes)
                    await emit(frame)
                } catch { failOutput() }
            }
            return
        }
        if method == "notifications/cancelled" {
            guard responseID == nil else {
                await emitError(id: responseID, code: -32600, message: "Invalid Request")
                return
            }
            if let params = fields["params"]?.objectValue,
               Set(params.keys).isSubset(of: ["requestId", "reason"]),
               let key = Self.key(params["requestId"]) {
                await cancel(key, code: -32800, message: "Request cancelled")
            }
            return
        }
        if responseID == nil && method.hasPrefix("notifications/") { return }
        let key = Self.key(responseID) ?? "anonymous:" + UUID().uuidString
        guard entries[key] == nil else {
            await emitError(id: responseID, code: -32600, message: "Request ID is already in flight")
            return
        }
        guard entries.count + pendingWrites < configuration.maximumInFlightRequests else {
            if responseID != nil {
                await emitError(id: responseID, code: -32000, message: "Too many in-flight requests",
                    terminal: .inFlight(limit: configuration.maximumInFlightRequests,
                                        used: entries.count + pendingWrites))
            }
            return
        }
        // Preserve arbitrary JSON numeric IDs independently of legacy scripting
        // number conversion. The handler sees a surrogate; the terminal restores
        // the exact admitted ID lexeme, including explicit null.
        let progressToken = responseID != nil && method == "tools/call"
            ? Self.admittedProgressToken(fields["params"]?.objectValue?["_meta"]?.objectValue?["progressToken"])
            : nil
        // Metadata is opaque to tool execution after strict admission. Keep the
        // exact progress token here, and avoid converting unrelated metadata numbers
        // through the legacy finite-number scripting representation.
        if method == "tools/call", var params = fields["params"]?.objectValue,
           params["_meta"]?.objectValue != nil {
            params.removeValue(forKey: "_meta")
            fields["params"] = .object(params)
        }
        if responseID != nil { fields["id"] = .number("0") }
        let mutation = method == "tools/call"
            && mutatingCommands.contains(fields["params"]?.objectValue?["name"]?.stringValue ?? "")
        let token = UUID()
        do { try fence.admit {
        entries[key] = Entry(token: token, request: Phase2ProductionJSONValue.object(fields).canonicalJSONBytes(),
                             responseID: responseID, mutation: mutation, outcome: MCPMutationOutcome())
        let duration = configuration.maximumToolDurationNanoseconds
        entries[key]?.deadline = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: duration) } catch { return }
            await self?.expire(key, token: token)
        }
        if let progressToken, let source = progressSource, !source.isSettled {
            entries[key]?.progress = Task { [weak self] in
                await self?.reportProgress(key, token: token, progressToken: progressToken, source: source)
            }
        }
        if mutation {
            mutationQueue.append(key)
            startNextMutation()
        } else { start(key) }
        } } catch { failOutput() }
    }

    private func reportProgress(_ key: String, token: UUID,
                                progressToken: Phase2ProductionJSONValue,
                                source: MCPStartupStatus) async {
        var previous = -1
        while !Task.isCancelled {
            do { try await Task.sleep(nanoseconds: progressIntervalNanoseconds) }
            catch { return }
            guard !Task.isCancelled, let entry = entries[key], entry.token == token,
                  !entry.terminal, !outputFailed else { return }
            let value = source.snapshot()
            // Failure keeps its last count but must not emit a completion notification.
            if value.state == "failed" { return }
            if value.completedPhases > previous {
                previous = value.completedPhases
                let message = value.state == "ready" ? "ready" : (value.phase?.rawValue ?? "analyzing")
                let notification = Phase2ProductionJSONValue.object([
                    "jsonrpc": .string("2.0"),
                    "method": .string("notifications/progress"),
                    "params": .object([
                        "progressToken": progressToken,
                        "progress": .integer(value.completedPhases),
                        "total": .integer(9),
                        "message": .string(message)
                    ])
                ]).canonicalJSONBytes()
                guard MCPFrameAdmission.fits(notification, maximumBytes: configuration.maximumOutputBytes) else { return }
                await emit(notification)
            }
            if value.state == "ready" { return }
        }
    }

    private static func admittedProgressToken(_ value: Phase2ProductionJSONValue?) -> Phase2ProductionJSONValue? {
        guard let value else { return nil }
        switch value {
        case .string: return value
        case .number(let lexeme):
            // Preserve arbitrary-size integer lexemes without routing through Double.
            let digits = lexeme.first == "-" ? lexeme.dropFirst() : lexeme[...]
            guard !digits.isEmpty, digits.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return nil }
            return value
        default: return nil
        }
    }

    private func start(_ key: String) {
        guard accepting, !fence.isFailed, let entry = entries[key] else { return }
        let operation = execute
        let fence = fence
        entries[key]?.task = Task.detached { [weak self] in
            let response: Data? = await MCPExecutionFence.$connection.withValue(fence) {
                await MCPExecutionFence.$outcome.withValue(entry.outcome) {
                    guard !fence.isFailed else { return nil }
                    return await operation(entry.request)
                }
            }
            await self?.complete(key, token: entry.token, response: response)
        }
    }

    private func startNextMutation() {
        guard accepting, !fence.isFailed, activeMutation == nil else { return }
        while !mutationQueue.isEmpty {
            let key = mutationQueue.removeFirst()
            guard entries[key] != nil else { continue }
            activeMutation = key
            start(key)
            return
        }
    }

    private func expire(_ key: String, token: UUID) async {
        guard entries[key]?.token == token else { return }
        await cancel(key, code: -32001, message: "Request deadline exceeded")
    }
    private func cancel(_ key: String, code: Int, message: String) async {
        guard var entry = entries[key], !entry.terminal else { return }
        entry.task?.cancel()
        entry.deadline?.cancel()
        entry.progress?.cancel()
        // A running mutation owns the truth of its commit. Its result must decide
        // whether cancellation preceded admission or arrived after durable work.
        if entry.mutation && entry.task != nil {
            if entry.cancellation == nil { entry.cancellation = (code, message) }
            entries[key] = entry
            await entry.progress?.value
            return
        }
        entry.terminal = true
        entry.drainingTerminal = true
        entries[key] = entry
        if entry.task == nil { mutationQueue.removeAll { $0 == key } }
        // Retain the ID and admission slot until any started progress write ends.
        await entry.progress?.value
        guard var current = entries[key], current.token == entry.token else { return }
        current.drainingTerminal = false
        if current.task == nil {
            entries.removeValue(forKey: key)
            mutationQueue.removeAll { $0 == key }
        } else {
            entries[key] = current
        }
        if entry.responseID != nil { await emitError(id: entry.responseID, code: code, message: message) }
    }

    private func complete(_ key: String, token: UUID, response: Data?) async {
        guard let entry = entries[key], entry.token == token else { return }
        entry.deadline?.cancel()
        entry.progress?.cancel()
        if entry.drainingTerminal {
            // Cancellation owns the terminal write and will retire this entry
            // after draining progress. Record that the execution has acknowledged.
            entries[key]?.task = nil
            return
        }
        entries[key]?.terminal = true
        entries[key]?.drainingTerminal = true
        await entry.progress?.value
        guard entries[key]?.token == token else { return }
        entries.removeValue(forKey: key)
        if !entry.terminal, let id = entry.responseID {
            if entry.outcome.snapshot == .notStarted, let cancellation = entry.cancellation,
               let response,
               let fields = try? Phase2StrictJSONParser().parse(response, limits: .providerEnvelope).objectValue,
               fields["error"]?.objectValue?["code"] == .number("-32800") {
                await emitError(id: id, code: cancellation.code, message: cancellation.message)
            } else {
                do {
                    var fallback: String, compact: String
                    switch entry.outcome.snapshot {
                    case .notStarted: fallback = "Response exceeds limit"; compact = ""
                    case .unknown: fallback = "Mutation outcome unknown; do not retry automatically."; compact = "Outcome unknown; no retry"
                    case .returned: fallback = "Operation returned; do not retry automatically."; compact = "Returned; no retry"
                    case .committed: fallback = "Mutation committed; do not retry."; compact = "Committed; no retry"
                    case .rolledBack: fallback = "Write rolled back; read fresh state before retrying."; compact = "Rolled back"
                    }
                    if let receipt = entry.outcome.batchReceipt {
                        fallback = receipt.summary + "; reporting failed. Do not retry automatically."
                        compact = fallback
                    }
                    let restored = try MCPFrameAdmission.response(response ?? Data(), id: id,
                        maximumBytes: configuration.maximumOutputBytes, failureMessage: fallback, compactMessage: compact,
                        receiptResultText: entry.outcome.batchReceipt.map {
                            $0.summary + "; response exceeds limit. Do not retry automatically."
                        })
                    await emit(restored)
                } catch { failOutput() }
            }
        }
        if activeMutation == key { activeMutation = nil; startNextMutation() }
        resumeDrainIfEmpty()
    }

    /// EOF retires read results and queued work, but waits for every running task's
    /// cleanup acknowledgment and every terminal write before transport teardown.
    /// Running mutations preserve committed truth rather than claim rollback.
    func finishInput() async {
        accepting = false
        let keys = Array(entries.keys)
        for key in keys {
            await cancel(key, code: -32800, message: "Input closed")
        }
        resumeDrainIfEmpty()
        if !entries.isEmpty || pendingWrites != 0 {
            await withCheckedContinuation { drainWaiters.append($0) }
        }
    }

    private func resumeDrainIfEmpty() {
        guard entries.isEmpty, pendingWrites == 0 else { return }
        let waiters = drainWaiters
        drainWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
    }

    private func emitError(id: Phase2ProductionJSONValue?, code: Int, message: String,
                           terminal suppliedTerminal: MCPServerTerminal? = nil) async {
        let correlation = id ?? .null
        let terminal: MCPServerTerminal?
        if let suppliedTerminal {
            terminal = suppliedTerminal
        } else if code == -32001 {
            terminal = .deadline(limitNanoseconds: configuration.maximumToolDurationNanoseconds,
                                 usedNanoseconds: nil)
        } else {
            terminal = nil
        }
        do {
            let bounded = try MCPFrameAdmission.response(
                Self.error(id: correlation, code: code, message: message, terminal: terminal),
                id: correlation, maximumBytes: configuration.maximumOutputBytes)
            await emit(bounded)
        } catch { failOutput() }
    }

    private func emit(_ data: Data) async {
        guard !outputFailed, !fence.isFailed else { return }
        pendingWrites += 1
        defer { pendingWrites -= 1; resumeDrainIfEmpty() }
        do {
            guard MCPFrameAdmission.fits(data, maximumBytes: configuration.maximumOutputBytes) else {
                throw MCPFrameAdmission.Failure.unrepresentable
            }
            try await output(data)
        } catch { failOutput() }
    }

    private func failOutput() {
        fence.fail()
        // Keep running tasks until their owned cleanup acknowledges cancellation.
        outputFailed = true
        accepting = false
        for key in Array(entries.keys) {
            guard var entry = entries[key] else { continue }
            entry.task?.cancel()
            entry.deadline?.cancel()
            entry.progress?.cancel()
            entry.terminal = true
            if entry.task == nil { entries.removeValue(forKey: key) }
            else { entries[key] = entry }
        }
        mutationQueue.removeAll()
        resumeDrainIfEmpty()
    }

    private static func error(id: Phase2ProductionJSONValue, code: Int, message: String,
                              terminal: MCPServerTerminal? = nil) -> Data {
        var fields: [String: Phase2ProductionJSONValue] = [
            "code": .integer(code), "message": .string(message)
        ]
        if let terminal { fields["data"] = terminal.phaseValue }
        return Phase2ProductionJSONValue.object(["jsonrpc": .string("2.0"), "id": id,
            "error": .object(fields)]).canonicalJSONBytes()
    }

    private static func key(_ value: Phase2ProductionJSONValue?) -> String? {
        switch value {
        case .null?: return "null"
        case .string(let text)? where text.utf8.count <= 256
            && !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains):
            return "string:" + text
        case .number(let source)? where source.utf8.count <= 256:
            let negative = source.first == "-"
            let unsigned = negative ? String(source.dropFirst()) : source
            let parts = unsigned.lowercased().split(separator: "e")
            let decimal = parts[0].split(separator: ".", omittingEmptySubsequences: false)
            var digits = String(decimal.joined().drop(while: { $0 == "0" }))
            if digits.isEmpty { return "number:0" }
            let exponent: Int64
            if parts.count == 2 {
                guard let parsed = Int64(parts[1]) else { return "number:" + source }
                exponent = parsed
            } else { exponent = 0 }
            let scaled = exponent.subtractingReportingOverflow(Int64(decimal.count == 2 ? decimal[1].count : 0))
            guard !scaled.overflow else { return "number:" + source }
            var scale = scaled.partialValue
            while digits.last == "0", scale < Int64.max { digits.removeLast(); scale += 1 }
            return "number:" + (negative ? "-" : "") + digits + "e" + String(scale)
        default: return nil
        }
    }
}

/// Strict JSON admission shared by the two headless adapters. The Phase 2 parser rejects
/// duplicate keys, malformed Unicode, excessive depth/token counts, and trailing bytes before
/// the value is converted into the legacy scripting DTO.
enum HeadlessJSON {
    static func decode(_ data: Data, maximumBytes: Int) throws -> ScriptValue {
        let limits = Phase2StrictJSONLimits(
            maximumBytes: maximumBytes,
            maximumDepth: 16,
            maximumTokens: 100_000,
            maximumMembersAndElements: 50_000
        )
        let value: Phase2ProductionJSONValue
        do {
            value = try Phase2StrictJSONParser().parse(data, limits: limits)
        } catch {
            throw HeadlessJSONError.invalid
        }
        return try convert(value)
    }

    /// JSON Schema integers include decimal/exponent spellings (1.0 and 1e3).
    /// Normalize their decimal digits before any floating-point conversion so an
    /// address or signed delta above 2^53 never silently rounds to another byte.
    /// The strict JSON parser has already validated the number grammar.
    private static func exactInteger(_ source: String) -> Int64? {
        if let direct = Int64(source) { return direct }
        let negative = source.first == "-"
        let unsigned = negative ? String(source.dropFirst()) : source
        let exponentParts = unsigned.split(whereSeparator: { $0 == "e" || $0 == "E" })
        guard exponentParts.count == 1 || exponentParts.count == 2 else { return nil }
        let mantissa = exponentParts[0]
        let decimalParts = mantissa.split(separator: ".", omittingEmptySubsequences: false)
        guard decimalParts.count == 1 || decimalParts.count == 2 else { return nil }
        let fractionCount = decimalParts.count == 2 ? decimalParts[1].count : 0
        var digits = decimalParts.joined()
        guard !digits.isEmpty, digits.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
        digits = String(digits.drop(while: { $0 == "0" }))
        if digits.isEmpty { return 0 }
        let exponent: Int64
        if exponentParts.count == 2 {
            let exponentSource = String(exponentParts[1])
            let exponentNegative = exponentSource.first == "-"
            let magnitudeSource = (exponentSource.first == "+" || exponentNegative)
                ? String(exponentSource.dropFirst()) : exponentSource
            let magnitude = String(magnitudeSource.drop(while: { $0 == "0" }))
            guard magnitude.isEmpty || magnitude.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  let value = Int64(magnitude.isEmpty ? "0" : magnitude) else { return nil }
            exponent = exponentNegative ? -value : value
        } else {
            exponent = 0
        }
        let scale = exponent.subtractingReportingOverflow(Int64(fractionCount))
        guard !scale.overflow else { return nil }
        if scale.partialValue >= 0 {
            guard digits.count <= 19, scale.partialValue <= Int64(19 - digits.count) else { return nil }
            digits += String(repeating: "0", count: Int(scale.partialValue))
        } else {
            // Avoid negating Int64.min; a nonzero fractional value cannot be an integer.
            guard scale.partialValue >= -Int64(digits.count) else { return nil }
            let removed = Int(-scale.partialValue)
            guard digits.suffix(removed).allSatisfy({ $0 == "0" }) else { return nil }
            digits.removeLast(removed)
        }
        guard !digits.isEmpty, digits.count <= 19 else { return nil }
        return Int64((negative ? "-" : "") + digits)
    }

    static func convert(_ value: Phase2ProductionJSONValue) throws -> ScriptValue {
        switch value {
        case .null:
            return .null
        case .bool(let value):
            return .bool(value)
        case .number(let source):
            if let integer = exactInteger(source) { return .int(integer) }
            guard let number = Double(source), number.isFinite else {
                throw HeadlessJSONError.invalid
            }
            return .double(number)
        case .string(let value):
            return .string(value)
        case .array(let values):
            return .array(try values.map(convert))
        case .object(let fields):
            return .object(try fields.mapValues(convert))
        }
    }
}

enum HeadlessAutomationAuthorityError: LocalizedError, Equatable {
    case unavailableCommand
    case invalidArguments
    case invalidScript

    var errorDescription: String? {
        switch self {
        case .unavailableCommand: "The command is unavailable through headless automation."
        case .invalidArguments: "The command arguments are invalid for headless automation."
        case .invalidScript: "The script is invalid for headless automation."
        }
    }
}

/// Closed authority for the legacy external adapters. New scripting commands do not silently
/// become remotely callable. In particular, the filesystem-bearing commands are intentionally
/// absent: headless clients cannot read arbitrary dSYMs, write arbitrary paths, or emit a whole
/// patched binary through stdout.
@MainActor
enum HeadlessAutomationAuthority {
    struct ScriptStep {
        let command: String
        let arguments: ScriptValue
    }

    static let maximumScriptSteps = 1_024
    static let maximumContainerMembers = 4_096
    static let maximumArgumentStringBytes = 256 * 1_024
    static let maximumListRows = 10_000
    static let maximumReadBytes = 1 * 1_024 * 1_024
    /// The bounded search engine admits 256 UTF-8 bytes (after trimming); that limit is a
    /// performance bound, so the surface documents and enforces the same number. A longer query
    /// is refused with `{error: "invalidPattern", detail: "tooLong"}` (`searchRefusal`).
    static let maximumSearchQueryBytes = 256

    private static let allowedCommandNames: Set<String> = [
        "call-graph", "call-path",
        "add-bookmark", "add-bookmarks", "add-xref", "add-xrefs", "annotation-gaps", "basic-blocks", "bookmarks", "bundle-info", "callees", "callers",
        "call-argument-audit", "clear-local-label", "clear-patch", "clear-register-name",
        "clear-segment-override", "clear-segment-overrides", "commands", "containing-function", "decompile", "demangle", "define-type",
        "define-types-from-c", "exports", "functions", "function-references", "endpoint-references", "function-facts", "implementations", "goto", "imports", "info",
        "instructions", "list-image-types", "list-types", "local-labels", "make-alignment", "make-array",
        "make-arrays", "make-alignments", "make-data", "make-procedure", "make-string", "make-strings", "make-undefined", "manual-xrefs",
        "name-at", "neon-hitrate", "open-workspace", "parameter-binding-audit", "patch-bytes", "read-bytes", "read-evidence",
        "rebase-segment", "rebase-segments", "reconstruction-jobs", "register-names", "relocations", "remove-bookmark", "remove-bookmarks", "rename", "rename-register", "rename-registers", "clear-register-names", "set-stack-locals",
        "rename-segment", "rename-segments", "resolve-symbol", "save-workspace", "search", "sections", "segment-overrides",
        "set-color", "set-colors", "set-comment", "set-local-label", "set-operand-format", "set-signature", "set-signatures",
        "set-data", "set-procedures", "set-tag", "set-tags", "set-type", "set-undefined", "slices", "strings", "suppress-xref", "suppress-xrefs", "symbols", "xrefs",
        // DP04 C2: durable stack local rename/retype and the local listing (orphans included).
        "set-stack-local", "stack-locals",
        // DP04 D2: struct recovery (read-only candidate; explicit acceptance into the catalog).
        "recover-struct-candidate", "accept-struct-candidate",
        // Read-only single-target resolution of indirect calls through memory slots.
        "indirect-call-targets",
        // VA4 slice F: read-only saved-bytes checkpoint over the live store (process: same).
        "verified-checkpoint", "verified-commit", "verified-checkpoint-isolated",
        "open-claim", "record-callee-outcome", "claim-status",
        "set-names", "set-comments", "set-local-labels", "set-operand-formats", "set-types", "undo-last",
    ]

    static let harnessCommands: Set<String> = ["neon-hitrate", "reconstruction-jobs"]
    private static let xrefKinds = [XRefKind.call, XRefKind.string, XRefKind.selref, XRefKind.classref, XRefKind.data]

    /// The existing headless commands plus the navigator commands (`MCPServer+Navigator.swift`),
    /// which are closed-list members like the rest: catalog exposure and execution both use it.
    static var availableCommands: [ScriptingCommandInfo] {
        WorkspaceScriptingAPI.availableCommands.filter { allowedCommandNames.contains($0.name) }
            + NavigatorMCPCommands.catalog
    }

    /// Built once per process from the authoritative builder above; consumers read this snapshot.
    static let catalogSnapshot = MCPCatalogSnapshot.capture(availableCommands)

    private static func admits(_ command: String) -> Bool {
        allowedCommandNames.contains(command) || NavigatorMCPCommands.handles(command)
    }

    /// Describes the existing headless command contract. It does not grant authority:
    /// both catalog exposure and execution still use the closed command allowlist.
    static func inputSchema(for command: ScriptingCommandInfo) -> ScriptValue {
        var properties: [String: ScriptValue] = [:]
        for argument in command.arguments {
            properties[argument] = argumentSchema(command: command.name, argument: argument)
        }
        var schema: [String: ScriptValue] = [
            "type": .string("object"),
            "properties": .object(properties),
            "additionalProperties": .bool(false),
        ]
        let required = requiredArguments(for: command.name)
        if !required.isEmpty { schema["required"] = .array(required.map(ScriptValue.string)) }

        // Legacy function resolution prefers the name when both selectors are present.
        // The call-audit resolver separately requires exactly one selector.
        if command.arguments.contains("function") && command.arguments.contains("address") {
            let keyword = command.name == "call-argument-audit" ? "oneOf" : "anyOf"
            var alternatives = [requiredSchema(["function"]), requiredSchema(["address"])]
            if command.arguments.contains("selector") { alternatives.append(requiredSchema(["selector"])) }
            if command.arguments.contains("selectors") { alternatives.append(requiredSchema(["selectors"])) }
            schema[keyword] = .array(alternatives)
        } else if command.name == "xrefs" {
            schema["anyOf"] = .array([requiredSchema(["to"]), requiredSchema(["from"])])
        } else if command.name == "patch-bytes" {
            schema["anyOf"] = .array([
                requiredSchema(["bytes"]),
                .object([
                    "required": .array([.string("nop")]),
                    "properties": .object(["nop": .object(["const": .bool(true)])]),
                ]),
            ])
        }
        if command.name == "set-signature" {
            schema["not"] = requiredSchema(["isNoReturn", "noReturnState"])
        }
        return .object(schema)
    }

    private static func requiredSchema(_ names: [String]) -> ScriptValue {
        .object(["required": .array(names.map(ScriptValue.string))])
    }

    private static func requiredArguments(for command: String) -> [String] {
        if NavigatorMCPCommands.handles(command) { return NavigatorMCPCommands.requiredArguments(for: command) }
        switch command {
        case "call-graph": return ["root"]
        case "call-path": return ["from", "to"]
        case "read-evidence": return ["operation"]
        case "verified-checkpoint": return ["expectation"]
        case "verified-commit": return ["address", "field", "value"]
        case "verified-checkpoint-isolated": return ["operations"]
        case "rename": return ["address", "name"]
        case "set-comment": return ["address", "comment"]
        case "set-tag": return ["address", "tag"]
        case "set-names", "set-comments", "set-local-labels", "set-operand-formats", "set-types", "rename-registers", "clear-register-names", "set-stack-locals", "set-tags", "set-colors", "add-xrefs", "suppress-xrefs", "add-bookmarks", "remove-bookmarks", "set-signatures", "rename-segments", "rebase-segments", "make-arrays", "make-strings", "make-alignments", "set-data", "set-procedures", "set-undefined": return ["entries"]
        case "set-type": return ["address", "type"]
        case "set-color": return ["address", "color"]
        case "set-operand-format": return ["address", "format"]
        case "set-local-label": return ["address", "label"]
        case "make-array": return ["address", "count"]
        case "make-alignment": return ["address", "boundary"]
        case "rename-register": return ["register", "name"]
        case "clear-register-name": return ["register"]
        case "set-stack-local": return ["local"]
        case "recover-struct-candidate": return ["parameter"]
        case "accept-struct-candidate": return ["parameter", "candidate", "name"]
        case "add-xref", "suppress-xref": return ["from", "to"]
        case "goto", "search": return ["query"]
        case "open-workspace": return ["path"]
        case "resolve-symbol", "demangle", "define-type": return ["name"]
        case "define-types-from-c": return ["source"]
        case "rename-segment", "clear-segment-override": return ["section"]
        case "clear-segment-overrides": return ["entries"]
        case "rebase-segment": return ["section", "delta"]
        case "read-bytes", "name-at", "containing-function", "make-data", "make-procedure", "make-string",
             "make-undefined", "patch-bytes", "clear-patch", "set-signature",
             "add-bookmark", "remove-bookmark", "clear-local-label":
            return ["address"]
        case "implementations": return ["selector"]
        case "endpoint-references": return ["host"]
        default: return []
        }
    }

    private static func argumentSchema(command: String, argument: String) -> ScriptValue {
        if argument == "basedOnGeneration" {
            return .object(["type": .array([.string("string"), .string("null")]),
                            "format": .string("uuid"),
                            "description": .string("Optional analysis generation from the reply's generation text block (also result._meta.generation); null or omission retains legacy unconditional writes. A mismatch is staleEvidence with basedOnGeneration and currentGeneration.")])
        }
        if command == WorkspaceScriptingAPI.verifiedCommitCommand { return WorkspaceScriptingAPI.verifiedCommitArgumentSchema(argument) }
        if command == WorkspaceScriptingAPI.verifiedCheckpointIsolatedCommand { return WorkspaceScriptingAPI.verifiedCheckpointIsolatedArgumentSchema(argument) }
        if NavigatorMCPCommands.handles(command) { return NavigatorMCPCommands.argumentSchema(argument) }
        func integer(_ minimum: Int64, _ maximum: Int64) -> ScriptValue {
            .object([
                "type": .string("integer"), "minimum": .int(minimum), "maximum": .int(maximum),
            ])
        }
        let string: ScriptValue = .object(["type": .string("string")])
        let boolean: ScriptValue = .object(["type": .string("boolean")])
        switch (command, argument) {
        case ("function-facts", "function"):
            return .object(["type": .string("string"), "maxLength": .int(256),
                "description": .string("Raw or display name, or a 0x-hex address used when no name matches; at most 256 UTF-8 bytes.")])
        case ("function-facts", "imageSlot"):
            return .object(["anyOf": .array([integer(0, Int64(Int32.max)), string]),
                "description": .string("Read this loaded image slot or owner UUID; omitted reads the primary image.")])
        case ("call-graph", "root"), ("call-path", "from"), ("call-path", "to"):
            return .object(["oneOf": .array([
                .object(["type": .string("integer"), "minimum": .int(0)]),
                .object(["type": .string("string"), "pattern": .string("^0x[0-9a-fA-F]{1,16}$")])])])
        case ("call-graph", "depth"), ("call-path", "maxDepth"): return integer(0, 16)
        case ("call-graph", "limit"), ("call-path", "limit"): return integer(1, 100)
        case ("call-graph", "direction"):
            return .object(["type": .string("string"), "enum": .array([.string("callers"), .string("callees")])])
        case ("call-graph", "cursor"), ("call-path", "cursor"):
            return .object(["type": .string("string"), "maxLength": .int(39),
                "pattern": .string("^c1:[0-9A-F-]{36}$"),
                "description": .string("Opaque continuation; repeat selectors and imageSlot. limit may be reduced. Old input cursors survive output-byte refusal until eviction/expiry.")])
        case ("set-color", "color"):
            return .object([
                "type": .string("string"),
                "enum": .array(([""] + ColorTag.allCases.map(\.rawValue)).map(ScriptValue.string)),
                "description": .string("An exact color tag; empty clears it. Null is not accepted."),
            ])
        case ("decompile", "backend"):
            return .object(["type": .string("string"), "enum": .array([.string("native"), .string("macir"), .string("both")]),
                "description": .string("Choose or compare decompilers; absent tries native and falls back to MacIR.")])
        case ("decompile", "format"):
            return .object(["type": .string("string"), "enum": .array([.string("text"), .string("lines")]),
                "description": .string("Return one code representation; MCP defaults to text. Native complete describes the source document. Native responseComplete requires a complete, untruncated document and all rendered lines in this reply; a terminal suffix is not complete. MacIR replies do not claim native completeness.")])
        case ("set-operand-format", "format"):
            return .object(["type": .string("string"),
                            "enum": .array(([""] + OperandFormat.allCases.map(\.rawValue)).map(ScriptValue.string))])
        case ("decompile", "lineRange"):
            return .object(["type": .string("string"), "maxLength": .int(32),
                "pattern": .string("^[1-9][0-9]{0,8}-[1-9][0-9]{0,8}$"),
                "description": .string("Inclusive 1-based line positions a-b; cannot accompany cursor.")])
        case ("decompile", "fold"):
            return .object(["type": .string("array"),
                "items": .object(["type": .string("string"), "enum": .array([.string("arc")])]),
                "description": .string("Opt-in presentation folds; supported: arc (remove proven ARC retain/release calls, non-SSA only). Requires or implies backend macir and is refused with native or both. Replies add folded, foldedEvents and foldRefused. An empty array is no fold.")])
        case ("decompile", "cursor"):
            return .object(["type": .string("string"), "maxLength": .int(1_024),
                "description": .string("Continue nextCursor with the same selector and image; restart if stale.")])
        case ("demangle", "name"):
            return .object(["type": .string("string"), "maxLength": .int(8_192)])
        case ("verified-checkpoint", "expectation"): return .object(["type": .string("object"), "description": .string("Operation IDs plus expected fields (schemaVersion 1; workspaceID, documentID, writerInstallationIDs, writerProcessID, operations); at most 256 operations and 65536 bytes.")])
        case ("verified-checkpoint", "imageSlot"): return integer(0, Int64(Int32.max))
        case ("read-evidence", "operation"):
            // Preserve the new external subset; discovery never admits native,
            // shell, mutation, principal, or caller-supplied replay authority.
            return .object([
                "type": .string("string"),
                "enum": .array(TypedReadRegistry.ExternalOperation.allCases.map {
                    .string($0.rawValue)
                }),
            ])
        case ("callers", "limit"), ("callees", "limit"):
            return integer(1, 500)
        case ("xrefs", "page"), ("callers", "page"), ("callees", "page"):
            return .object(["type": .string("boolean"), "description": .string("Opt in to bounded source-order edge pages; follow nextCursor even when a page is empty.")])
        case ("xrefs", "cursor"), ("callers", "cursor"), ("callees", "cursor"):
            return .object(["type": .string("string"), "maxLength": .int(39), "description": .string("Opaque graph cursor; repeat the same selectors.")])
        case ("xrefs", "detail"), ("callers", "detail"), ("callees", "detail"):
            return .object(["type": .string("string"), "enum": .array([.string("edges")]), "description": .string("Required for graph pages; returns edge identities without names.")])
        case ("endpoint-references", "host"):
            return .object(["type": .string("string"), "maxLength": .int(2_048),
                "description": .string("Exact hostname (case-insensitive, no suffix match) or an http, https, ws or wss URL. Query values, fragments, user-info and ports are discarded and never echoed.")])
        case ("endpoint-references", "path"):
            return .object(["type": .string("string"), "maxLength": .int(2_048),
                "description": .string("Optional literal path starting with /. Strings with {name}, %@ or %d placeholder segments match as pathTemplate. A query string or fragment is dropped.")])
        case ("endpoint-references", "method"):
            return .object(["type": .string("string"), "maxLength": .int(16),
                "description": .string("Optional HTTP method. It filters only strings that carry a method token.")])
        case ("endpoint-references", "limit"):
            return integer(1, Int64(WorkspaceScriptingAPI.maximumListPageLimit))
        case ("endpoint-references", "cursor"):
            return .object(["type": .string("string"), "maxLength": .int(1_024),
                "description": .string("A nextCursor from the same query and image.")])
        case (_, "limit"):
            return integer(0, Int64(maximumListRows))
        case ("functions", "page"), ("strings", "page"), ("symbols", "page"):
            return .object([
                "type": .string("boolean"),
                "description": .string("Opt in to a bounded page envelope; omitted, null or false keeps the legacy array."),
            ])
        case ("functions", "cursor"), ("strings", "cursor"), ("symbols", "cursor"):
            return .object([
                "type": .string("string"), "maxLength": .int(1_024),
                "description": .string("Continue from nextCursor with page:true; a stale cursor requires restarting without it."),
            ])
        case ("functions", "nameContains"), ("symbols", "nameContains"), ("sections", "nameContains"),
             ("imports", "nameContains"), ("exports", "nameContains"), ("relocations", "nameContains"):
            return .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024)])
        case ("functions", "regex"), ("symbols", "regex"):
            return .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(256)])
        case ("symbols", "kind"):
            return .object([
                "type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024),
                "description": .string("One of " + ListRowFilter.allowedSymbolKinds.joined(separator: "|") + "."),
            ])
        case ("strings", "section"), ("strings", "contains"):
            return .object([
                "type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024),
                "description": .string("Exact qualified section name, or case-insensitive literal value substring."),
            ])
        case ("search", "mode"):
            return .object(["type": .string("string"),
                "enum": .array(BinarySearchMode.allCases.map { .string($0.rawValue) })])
        case ("add-xref", "kind"), ("suppress-xref", "kind"):
            return .object(["type": .string("string"),
                "enum": .array(xrefKinds.map(ScriptValue.string))])
        case ("search", "kind"):
            return .object([
                "type": .string("string"),
                "enum": .array(BinarySearchResult.Kind.allCases.map { .string($0.rawValue) }),
            ])
        // SW5 (dot 1251): discovery addition for the declaration format.
        case ("list-image-types", "format"):
            return .object([
                "type": .array([.string("string"), .string("null")]),
                "enum": .array([.string("declarations-v1"), .null]),
            ])
        case ("list-image-types", "kind"):
            return .object([
                "type": .string("string"),
                "enum": .array(TypeAtlasKind.allCases.map { .string($0.rawValue) }),
            ])
        case ("list-image-types", "page"):
            return .object([
                "type": .string("boolean"),
                "description": .string("Opt in to a bounded Type Atlas page with filters and continuation; name, nameContains or fields without page also page."),
            ])
        case ("list-image-types", "cursor"):
            return .object([
                "type": .string("string"), "maxLength": .int(1_024),
                "description": .string("Continue from nextCursor; restart if stale. A nextCursor from a default reply needs page:true, fields:\"full\", limit:1 and the original image/kind; page cursors keep their own filters and fields."),
            ])
        case ("list-image-types", "name"), ("list-image-types", "nameContains"):
            return .object([
                "type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024),
            ])
        case ("list-image-types", "fields"):
            return .object([
                "type": .string("string"), "enum": .array([.string("full"), .string("names")]),
            ])
        case ("info", "waitForReadyMs"):
            return integer(0, 25_000)
        case ("instructions", "count"):
            return integer(0, Int64(maximumListRows))
        case ("instructions", "annotate"):
            return .object(["type": .string("boolean"),
                "description": .string("Set true to add call-target names and data-target previews to rows; default false.")])
        case ("read-bytes", "count"):
            return integer(0, Int64(maximumReadBytes))
        case ("make-array", "count"):
            return integer(1, Int64(DataShapeOverride.maxElementCount))
        case ("make-array", "format"):
            return .object([
                "type": .string("string"),
                "enum": .array(([""] + OperandFormat.allCases.map(\.rawValue)).map(ScriptValue.string)),
                "description": .string("Optional array element display format. Omitted or empty leaves no format override; supplied values must be one of the listed strings."),
            ])
        case ("make-alignment", "boundary"):
            var boundaries: [ScriptValue] = []
            var value: Int64 = 2
            let maximum = Int64(DataShapeOverride.maxAlignment)
            while value <= maximum {
                boundaries.append(.int(value))
                // Avoid overflow even if the underlying limit changes later.
                guard value <= maximum / 2 else { break }
                value *= 2
            }
            return .object(["type": .string("integer"), "enum": .array(boundaries)])
        case ("make-string", "length"):
            return integer(1, min(Int64(maximumReadBytes), Int64(DataShapeOverride.maxStringLength)))
        case ("make-data", "isData"), ("make-procedure", "isProcedure"),
             ("make-undefined", "isUndefined"), ("patch-bytes", "nop"),
             ("set-signature", "isNoReturn"):
            return boolean
        case ("set-signature", "returnType"):
            return .object(["type": .array([.string("string"), .string("null")])])
        case ("set-signature", "args"):
            return .object([
                "type": .array([.string("array"), .string("null")]),
                "maxItems": .int(Int64(maximumContainerMembers)),
                "items": .object([
                    "type": .string("object"),
                    "properties": .object(["name": string, "type": string]),
                    "required": .array([.string("type")]),
                ]),
            ])
        case ("set-signature", "variadicState"):
            return .object([
                "type": .string("string"),
                "enum": .array(["unspecified", "fixed", "variadic"].map(ScriptValue.string)),
            ])
        case ("set-signature", "noReturnState"):
            return .object([
                "type": .string("string"),
                "enum": .array(["unspecified", "returns", "noReturn"].map(ScriptValue.string)),
            ])
        case ("define-type", "fields"):
            return .object([
                "type": .string("array"),
                "maxItems": .int(Int64(maximumContainerMembers)),
                "items": .object([
                    "type": .string("object"),
                    "properties": .object(["name": string, "type": string]),
                ]),
            ])
        case ("callers", "selector"), ("implementations", "selector"):
            return .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024),
                "description": .string("Objective-C selector, exactly as written, e.g. \"setDouble:forKey:\"; callers: use instead of function or address.")])
        case ("callers", "selectors"):
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(8), "uniqueItems": .bool(true),
                "items": .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024)]),
                "description": .string("Several Objective-C selectors in one call; returns each selector's send sites, as `selector` would, in one reply. Use instead of repeated selector calls.")])
        case ("callers", "address"):
            return .object([
                "anyOf": .array([string, integer(0, Int64.max)]),
                "description": .string("Unsigned address inside a known function; the function start is accepted for a zero-width function. An address or stub name outside every function returns the call-kind sites of xrefs with to, with fromFunction and fromFunctionName; zero sites preserve the refusal, and finite work/result budgets still apply. A function name takes precedence. Prefer a hexadecimal string to preserve all 64 bits."),
            ])
        case (_, "address"), (_, "from"), (_, "to"):
            return .object([
                "anyOf": .array([string, integer(0, Int64.max)]),
                "description": .string("Unsigned address. Exact-address tools use the address itself. Function-selector tools require a containing function (or the exact start of a zero-width function) and refuse uncovered addresses; a supplied function name takes precedence. Prefer a hexadecimal string to preserve all 64 bits."),
            ])
        case ("rebase-segment", "delta"):
            return .object(["anyOf": .array([string, integer(Int64.min, Int64.max)])])
        case ("search", "cursor"):
            return .object([
                "type": .string("string"), "maxLength": .int(1_024),
                "description": .string("A nextCursor from the same bounded search."),
            ])
        case ("search", "query"):
            return .object([
                "type": .string("string"),
                "description": .string(
                    "Text, regular expression or hex pattern; at most \(maximumSearchQueryBytes) UTF-8 bytes after trimming. A longer query, or an invalid regular expression, returns {error: \"invalidPattern\", detail}."
                ),
            ])
        case (_, WorkspaceScriptingAPI.imageSlotFilterArgument):
            // DEF-A04: row filter for search / callers / callees / xrefs; every row carries `imageSlot`.
            return .object([
                "anyOf": .array([integer(0, Int64(Int32.max)), string]),
                "description": .string(
                    "Restrict the rows to one loaded image: a slot index or an image-owner ID (UUID). Omit to search every image (search) or read the primary image (callers, callees, xrefs, function-references). Every row reports the `imageSlot` that produced it."
                ),
            ])
        case (_, WorkspaceScriptingAPI.imageSelectorArgument):
            // MS-19: optional; omitted means the primary image (never the focused image).
            return .object([
                "anyOf": .array([integer(0, Int64(Int32.max)), string]),
                "description": .string(
                    "Image to read: a slot index (0 is the primary image) or an image-owner ID (UUID). Omit for the primary image."
                ),
            ])
        case ("recover-struct-candidate", "parameter"), ("accept-struct-candidate", "parameter"):
            return integer(0, 7)
        case ("accept-struct-candidate", "choices"):
            return .object([
                "type": .string("array"),
                "items": .object([
                    "type": .string("object"),
                    "properties": .object(["offset": .object(["type": .string("integer")]),
                                           "width": .object(["type": .string("integer")])]),
                    "required": .array([.string("offset"), .string("width")]),
                    "additionalProperties": .bool(false),
                ]),
            ])
        case ("rename-registers", "entries"), ("clear-register-names", "entries"):
            var properties: [String: ScriptValue] = [
                "function": .object(["description": .string("A string function selector takes precedence; other values fall back to address.")]),
                "address": .object(["description": .string("Used when function is not a string; ignored otherwise.")]),
                "register": string,
            ]
            var required: [ScriptValue] = [.string("register")]
            if command == "rename-registers" { properties["name"] = string; required.append(.string("name")) }
            return .object([
                "type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"), "properties": .object(properties),
                                  "required": .array(required), "additionalProperties": .bool(false),
                                  "anyOf": .array([
                                      .object(["required": .array([.string("function")]), "properties": .object(["function": string])]),
                                      .object(["required": .array([.string("address")]), "properties": .object(["address": .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])])]),
                                  ])]),
            ])
        case ("set-data", "entries"), ("set-procedures", "entries"):
            let field = command == "set-data" ? "isData" : "isProcedure"
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"), "properties": .object(["address": address, field: .object(["type": .string("boolean")])]),
                    "required": .array([.string("address")]), "additionalProperties": .bool(false)])])
        case ("set-undefined", "entries"):
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"), "properties": .object(["address": address, "isUndefined": .object(["type": .string("boolean")])]),
                    "required": .array([.string("address")]), "additionalProperties": .bool(false)])])
        case ("make-arrays", "entries"):
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"), "properties": .object(["address": address,
                    "count": argumentSchema(command: "make-array", argument: "count"),
                    "elementType": argumentSchema(command: "make-array", argument: "elementType"),
                    "format": argumentSchema(command: "make-array", argument: "format")]),
                    "required": .array([.string("address"), .string("count")]), "additionalProperties": .bool(false)])])
        case ("make-strings", "entries"):
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"), "properties": .object(["address": address, "length": argumentSchema(command: "make-string", argument: "length")]),
                    "required": .array([.string("address")]), "additionalProperties": .bool(false)])])
        case ("make-alignments", "entries"):
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"), "properties": .object(["address": address, "boundary": argumentSchema(command: "make-alignment", argument: "boundary")]),
                    "required": .array([.string("address"), .string("boundary")]), "additionalProperties": .bool(false)])])
        case ("set-signatures", "entries"):
            let fields = ["address", "returnType", "args", "variadicState", "noReturnState", "isNoReturn"]
            let properties = Dictionary(uniqueKeysWithValues: fields.map { ($0, argumentSchema(command: "set-signature", argument: $0)) })
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                            "items": .object(["type": .string("object"), "properties": .object(properties),
                                              "required": .array([.string("address")]), "additionalProperties": .bool(false),
                                              "not": .object(["required": .array([.string("isNoReturn"), .string("noReturnState")])])])])
        case ("rename-segments", "entries"), ("rebase-segments", "entries"):
            let rebasing = command == "rebase-segments"
            var properties: [String: ScriptValue] = ["section": string]
            properties[rebasing ? "delta" : "name"] = rebasing
                ? .object(["anyOf": .array([string, .object(["type": .string("integer")])])])
                : .object(["anyOf": .array([string, .object(["type": .string("null")])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                            "items": .object(["type": .string("object"), "properties": .object(properties),
                                "required": .array((rebasing ? ["section", "delta"] : ["section"]).map(ScriptValue.string)), "additionalProperties": .bool(false)])])
        case ("set-tags", "entries"), ("set-colors", "entries"):
            let field = command == "set-tags" ? "tag" : "color"
            let text: ScriptValue = command == "set-colors" ? .object(["type": .string("string"), "enum": .array(([""] + ColorTag.allCases.map(\.rawValue)).map(ScriptValue.string))]) : string
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                            "items": .object(["type": .string("object"), "properties": .object(["address": address, field: text]),
                                              "required": .array([.string("address"), .string(field)]), "additionalProperties": .bool(false)])])
        case ("add-xrefs", "entries"), ("suppress-xrefs", "entries"):
            let address: ScriptValue = .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])
            let kind: ScriptValue = .object(["anyOf": .array([.object(["type": .string("string"), "enum": .array(xrefKinds.map(ScriptValue.string))]), .object(["type": .string("null")])])])
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                            "items": .object(["type": .string("object"), "properties": .object(["from": address, "to": address, "kind": kind]),
                                              "required": .array([.string("from"), .string("to")]), "additionalProperties": .bool(false)])])
        case ("add-bookmarks", "entries"), ("remove-bookmarks", "entries"):
            var properties: [String: ScriptValue] = ["address": .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])]
            if command == "add-bookmarks" { properties["name"] = .object(["anyOf": .array([string, .object(["type": .string("null")])])]) }
            return .object(["type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                            "items": .object(["type": .string("object"), "properties": .object(properties),
                                              "required": .array([.string("address")]), "additionalProperties": .bool(false)])])
        case ("set-stack-locals", "entries"):
            return .object([
                "type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object([
                    "type": .string("object"),
                    "properties": .object(["function": .object([:]), "address": .object([:]),
                                             "local": string, "name": string, "type": string]),
                    "required": .array([.string("local")]), "additionalProperties": .bool(false),
                    "allOf": .array([
                        .object(["anyOf": .array([
                            .object(["required": .array([.string("function")]), "properties": .object(["function": string])]),
                            .object(["required": .array([.string("address")]), "properties": .object(["address": .object(["anyOf": .array([string, .object(["type": .string("integer"), "minimum": .int(0)])])])])]),
                        ])]),
                        .object(["anyOf": .array([
                            .object(["required": .array([.string("name")]), "properties": .object(["name": string])]),
                            .object(["required": .array([.string("type")]), "properties": .object(["type": string])]),
                        ])]),
                    ]),
                ]),
            ])
        case ("clear-segment-overrides", "entries"):
            return .object([
                "type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object(["type": .string("object"),
                                  "properties": .object(["section": string]),
                                  "required": .array([.string("section")]),
                                  "additionalProperties": .bool(false)])
            ])
        case ("set-names", "entries"), ("set-comments", "entries"), ("set-local-labels", "entries"), ("set-operand-formats", "entries"), ("set-types", "entries"):
            let field = command == "set-names" ? "name" : (command == "set-local-labels" ? "label" : (command == "set-operand-formats" ? "format" : (command == "set-types" ? "type" : "comment")))
            let valueSchema: ScriptValue = command == "set-operand-formats"
                ? .object(["type": .string("string"),
                           "enum": .array(([""] + OperandFormat.allCases.map(\.rawValue)).map(ScriptValue.string))])
                : string
            return .object([
                "type": .string("array"), "minItems": .int(1), "maxItems": .int(1024),
                "items": .object([
                    "type": .string("object"),
                    "properties": .object([
                        "address": .object(["oneOf": .array([
                            .object(["type": .string("string")]),
                            .object(["type": .string("integer"), "minimum": .int(0)])
                        ])]),
                        field: valueSchema
                    ]),
                    "required": .array([.string("address"), .string(field)]),
                    "additionalProperties": .bool(false)
                ])
            ])
        default:
            return string
        }
    }

    static func scriptSteps(from script: ScriptValue) throws -> [ScriptStep] {
        guard case .array(let values) = script, values.count <= maximumScriptSteps else {
            throw HeadlessAutomationAuthorityError.invalidScript
        }
        return try values.map { value in
            guard case .object(let fields) = value,
                  Set(fields.keys).isSubset(of: ["command", "arguments"]),
                  let command = fields["command"]?.stringValue,
                  !command.isEmpty else {
                throw HeadlessAutomationAuthorityError.invalidScript
            }
            let arguments: ScriptValue
            switch fields["arguments"] {
            case .none, .some(.null):
                arguments = .object([:])
            case .some(let value):
                guard case .object = value else {
                    throw HeadlessAutomationAuthorityError.invalidScript
                }
                arguments = value
            }
            try validate(command: command, arguments: arguments)
            return ScriptStep(command: command, arguments: arguments)
        }
    }

    static func validate(command: String, arguments: ScriptValue) throws {
        do { try validateDiagnosed(command: command, arguments: arguments) }
        catch let error as ToolArgumentError { throw error.legacyError }
    }

    /// Used only by the MCP deciders; other callers retain legacy thrown errors.
    static func validateDiagnosed(command: String, arguments: ScriptValue) throws {
        guard admits(command) else { throw HeadlessAutomationAuthorityError.unavailableCommand }
        guard let commandInfo = catalogSnapshot.command(named: command),
              case .object(let inputFields) = arguments else {
            throw ToolArgumentError(field: "arguments", detail: "Field 'arguments' must be an object.", expected: "object")
        }
        // SW5 (dot 1251): retain the old diagnostic bytes for absent/null format.
        let allowed = commandInfo.arguments.filter {
            command != "list-image-types" || $0 != "format"
                || (inputFields["format"] != nil && inputFields["format"] != .null)
        }.sorted()
        if let unknown = inputFields.keys.sorted().first(where: { !commandInfo.arguments.contains($0) }) {
            let field = ToolArgumentError.fieldLabel(unknown)
            throw ToolArgumentError(field: field, detail: "Field '\(field)' is not an allowed argument.", allowed: allowed)
        }
        if commandInfo.mutates {
            do { _ = try WorkspaceScriptingAPI.basedOnGeneration(arguments) }
            catch let error as ScriptingError {
                throw ToolArgumentError(field: "basedOnGeneration", detail: error.localizedDescription,
                                        underlying: .scripting(error))
            }
        }
        // Keep existing command-specific exact-key parsers unchanged.
        let arguments = commandInfo.mutates ? WorkspaceScriptingAPI.withoutEvidencePrecondition(arguments) : arguments
        guard case .object(let fields) = arguments else { throw HeadlessAutomationAuthorityError.invalidArguments }
        do {
            try validateValue(arguments, depth: 0, field: "arguments")
        } catch {
            // Keep existing commands' diagnostics unchanged. A batch entry must
            // remain identifiable even when a generic cap rejects it first.
            if command == "set-names" || command == "set-comments" || MCPBatchReceiptBudget.commands.contains(command),
               let entries = fields["entries"]?.arrayValue {
                guard entries.count <= 1024 else {
                    throw ToolArgumentError(field: "entries[1024]", code: .outOfBounds,
                        detail: "Entry 1024 exceeds the 1024-entry batch limit.", maximum: 1024)
                }
                for (index, entry) in entries.enumerated() {
                    try validateValue(entry, depth: 2, field: "entries[\(index)]")
                }
            }
            throw error
        }
        for key in [WorkspaceScriptingAPI.imageSelectorArgument, WorkspaceScriptingAPI.imageSlotFilterArgument] {
            guard let image = fields[key] else { continue }
            switch image {
            case .int:
                try validateOptionalInteger(image, range: 0...Int64(Int32.max), field: key)
            case .string(let selector):
                guard selector.utf8.count <= 64 else {
                    throw ToolArgumentError(field: key, code: .outOfBounds,
                        detail: "Field '\(key)' must contain at most 64 UTF-8 bytes.", maximum: 64)
                }
            default:
                throw ToolArgumentError(field: key,
                    detail: "Field '\(key)' must be an integer slot or a string selector.",
                    expected: "integer or string")
            }
        }
        if NavigatorMCPCommands.handles(command) {
            try NavigatorMCPCommands.validateDiagnosed(command: command, fields: fields)
            return
        }

        if WorkspaceScriptingAPI.boundedCallCommands.contains(command) {
            do { _ = try WorkspaceScriptingAPI.boundedCallOptions(command, arguments) }
            catch let error as ScriptingError {
                throw ToolArgumentError(field: "arguments", detail: error.localizedDescription,
                                        underlying: .scripting(error))
            }
        }
        if WorkspaceScriptingAPI.graphPageCommands.contains(command) {
            do { _ = try WorkspaceScriptingAPI.graphPageOptions(command, arguments) }
            catch let error as ScriptingError {
                throw ToolArgumentError(field: "page", detail: error.localizedDescription,
                                        underlying: .scripting(error))
            }
        }

        func string(_ key: String, maximum: Int, required: Bool = false) throws {
            guard let value = fields[key] else {
                if required {
                    throw ToolArgumentError(field: key, detail: "Field '\(key)' is required.", expected: "string")
                }
                return
            }
            guard let text = value.stringValue else {
                throw ToolArgumentError(field: key, detail: "Field '\(key)' must be a string.", expected: "string")
            }
            guard text.utf8.count <= maximum else {
                throw ToolArgumentError(field: key, code: .outOfBounds,
                    detail: "Field '\(key)' must contain at most \(maximum) UTF-8 bytes.", maximum: Int64(maximum))
            }
        }
        switch command {
        case "function-facts": try string("function", maximum: 256)
        case "endpoint-references":
            try string("host", maximum: 2_048, required: true)
            try string("path", maximum: 2_048)
            try string("method", maximum: 16)
            try string("cursor", maximum: 1_024)
            try validateOptionalInteger(fields["limit"], range: 1...Int64(WorkspaceScriptingAPI.maximumListPageLimit), field: "limit")
        case "demangle": try string("name", maximum: 8_192, required: true)
        case "read-evidence":
            do { _ = try WorkspaceScriptingAPI.readEvidenceOperation(arguments) }
            catch let error as ScriptingError {
                throw ToolArgumentError(field: "operation",
                    detail: "Field 'operation' must name a supported read-evidence operation.",
                    expected: "string", allowed: TypedReadRegistry.ExternalOperation.allCases.map(\.rawValue).sorted(),
                    underlying: .scripting(error))
            }
        case "functions", "symbols", "strings", "imports", "exports", "sections", "relocations", "list-image-types":
            try validateOptionalInteger(fields["limit"], range: 0...Int64(maximumListRows), field: "limit")
            if command == "functions" || command == "symbols" {
                try string("nameContains", maximum: 1_024)
                try string("regex", maximum: 256)
            }
            if command == "sections" || command == "imports" || command == "exports" || command == "relocations" {
                try string("nameContains", maximum: 1_024)
                if let value = fields["nameContains"] {
                    do { _ = try ListRowFilter.parse(.object(["nameContains": value]), command: command) }
                    catch let error as ScriptingError {
                        throw ToolArgumentError(field: "nameContains",
                            detail: "Field 'nameContains' must be a non-empty string of at most 1024 UTF-8 bytes.",
                            expected: "string", underlying: .scripting(error))
                    }
                }
            }
            if command == "list-image-types", let format = fields["format"], format != .null,
               format != .string("declarations-v1") {
                throw ToolArgumentError(field: "format",
                    detail: "Field 'format' must be declarations-v1 or null.",
                    expected: "string or null", allowed: ["declarations-v1"])
            }
            if command == "symbols" { try string("kind", maximum: 1_024) }
            if command == "list-image-types", let kind = fields["kind"],
               kind.stringValue.flatMap(TypeAtlasKind.init(rawValue:)) == nil {
                throw ToolArgumentError(field: "kind", detail: "Field 'kind' must name a supported image type kind.",
                    expected: "string", allowed: TypeAtlasKind.allCases.map(\.rawValue).sorted())
            }
            if command == "strings" {
                try string("section", maximum: 1_024)
                try string("contains", maximum: 1_024)
            }
        case "search":
            if let raw = fields["mode"], raw != .null,
               raw.stringValue.flatMap(BinarySearchMode.init(rawValue:)) == nil {
                throw ToolArgumentError(field: "mode", detail: "Field 'mode' must be text, regex or hex.",
                    expected: "string", allowed: BinarySearchMode.allCases.map(\.rawValue).sorted())
            }
            let mode = BinarySearchMode(rawValue: fields["mode"]?.stringValue ?? "text") ?? .text
            do { _ = try WorkspaceScriptingAPI.searchKind(arguments, mode: mode) }
            catch let error as ScriptingError {
                let allowed = BinarySearchResult.Kind.allCases.filter {
                    mode == .hex ? $0 == .bytes : $0 != .bytes
                }.map(\.rawValue).sorted()
                throw ToolArgumentError(field: "kind", detail: "Field 'kind' must be allowed for the selected search mode.",
                    expected: "string", allowed: allowed, underlying: .scripting(error))
            }
            if let cursor = fields["cursor"], cursor != .null {
                guard let text = cursor.stringValue,
                      text.utf8.prefix(1_025).count <= 1_024 else {
                    throw ToolArgumentError(field: "cursor",
                        detail: "Field 'cursor' must be a nextCursor string from an earlier search.",
                        expected: "string")
                }
            }
        case "instructions":
            try validateOptionalInteger(fields["count"], range: 0...Int64(maximumListRows), field: "count")
            try validateOptionalBool(fields["annotate"], field: "annotate")
        case "read-bytes":
            try validateOptionalInteger(fields["count"], range: 0...Int64(maximumReadBytes), field: "count")
        case "make-string":
            try validateOptionalInteger(fields["length"], range: 1...Int64(maximumReadBytes), field: "length")
        case "make-array":
            try validateOptionalInteger(fields["count"], range: 1...Int64(DataShapeOverride.maxElementCount), field: "count")
        case "make-alignment":
            try validateOptionalInteger(fields["boundary"], range: 2...Int64(DataShapeOverride.maxAlignment), field: "boundary")
        case "rebase-segment":
            if let delta = fields["delta"] {
                switch delta {
                case .int, .string: break
                default:
                    throw ToolArgumentError(field: "delta", detail: "Field 'delta' must be an integer or string.",
                                            expected: "integer or string")
                }
            }
        case "make-data": try validateOptionalBool(fields["isData"], field: "isData")
        case "make-procedure": try validateOptionalBool(fields["isProcedure"], field: "isProcedure")
        case "make-undefined": try validateOptionalBool(fields["isUndefined"], field: "isUndefined")
        case "patch-bytes": try validateOptionalBool(fields["nop"], field: "nop")
        case "recover-struct-candidate":
            try validateOptionalInteger(fields["parameter"], range: 0...7, field: "parameter")
        case "accept-struct-candidate":
            try validateOptionalInteger(fields["parameter"], range: 0...7, field: "parameter")
            try string("candidate", maximum: 128, required: true)
            try string("name", maximum: 256, required: true)
            if let local = fields["local"],
               local.stringValue.flatMap(MacIRStackStorage.entryRange(forAuthoringKey:)) == nil {
                throw ToolArgumentError(field: "local", detail: "Field 'local' must be an entry-SP byte range lo:hi.",
                                        expected: "entry-SP byte range lo:hi")
            }
            if let choices = fields["choices"] {
                guard let list = choices.arrayValue else {
                    throw ToolArgumentError(field: "choices", detail: "Field 'choices' must be an array.", expected: "array")
                }
                guard list.count <= 256 else {
                    throw ToolArgumentError(field: "choices", code: .outOfBounds,
                        detail: "Field 'choices' must contain at most 256 entries.", maximum: 256)
                }
                for choice in list {
                    guard case .object(let entry) = choice, Set(entry.keys) == ["offset", "width"],
                          WorkspaceScriptingAPI.exactStructChoice(choice) != nil else {
                        throw ToolArgumentError(field: "choices",
                            detail: "Field 'choices' must contain objects with integer offset and width only.",
                            expected: "array of {offset: integer, width: integer}")
                    }
                }
            }
        case "set-stack-local":
            guard let local = fields["local"]?.stringValue,
                  MacIRStackStorage.entryRange(forAuthoringKey: local) != nil else {
                throw ToolArgumentError(field: "local", detail: "Field 'local' must be an entry-SP byte range lo:hi.",
                                        expected: "entry-SP byte range lo:hi")
            }
            guard fields["name"] != nil || fields["type"] != nil else {
                throw ToolArgumentError(field: "name", detail: "Field 'name' or field 'type' is required.",
                                        allowed: ["name", "type"])
            }
            try string("name", maximum: 1_024)
            try string("type", maximum: 1_024)
        case "rename-registers", "clear-register-names":
            let clearing = command == "clear-register-names"
            let entries: [ScriptValue]
            do { entries = try WorkspaceScriptingAPI.registerBatchEntries(arguments, clearing: clearing) }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
            for (index, entry) in entries.enumerated() {
                do { try validateDiagnosed(command: clearing ? "clear-register-name" : "rename-register", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let field = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: field, code: refusal.code, detail: "\(field): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "set-data", "set-procedures", "set-undefined":
            do {
                if command == "set-undefined" { _ = try WorkspaceScriptingAPI.undefinedBatchEntries(arguments) }
                else { _ = try WorkspaceScriptingAPI.dataProcedureBatchEntries(arguments, procedures: command == "set-procedures") }
            }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
        case "make-arrays", "make-strings", "make-alignments":
            do {
                if command == "make-arrays" { _ = try WorkspaceScriptingAPI.arrayShapeBatchEntries(arguments) }
                else if command == "make-strings" { _ = try WorkspaceScriptingAPI.stringShapeBatchEntries(arguments) }
                else { _ = try WorkspaceScriptingAPI.alignmentBatchEntries(arguments) }
            }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
        case "set-signatures":
            guard Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
                throw ToolArgumentError(field: "entries", detail: "Expected 1–1024 entries only.")
            }
            var seen = Set<UInt64>()
            for (index, entry) in entries.enumerated() {
                guard case .object(let row) = entry, let address = row["address"]?.addressValue else {
                    throw ToolArgumentError(field: "entries[\(index)].address", detail: "Expected an address.")
                }
                guard seen.insert(address).inserted else { throw ToolArgumentError(field: "entries[\(index)].address", detail: "Duplicate address.") }
                do { _ = try WorkspaceScriptingAPI.mergedSignature(entry, existing: nil) }
                catch let error as ScriptingError {
                    guard case .invalidArgument(let detail) = error else { throw error }
                    throw ToolArgumentError(field: "entries[\(index)]", detail: "entries[\(index)]: \(detail)", underlying: .scripting(error))
                }
                do { try validateDiagnosed(command: "set-signature", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let path = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: path, code: refusal.code, detail: "\(path): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "rename-segments", "rebase-segments":
            let rebasing = command == "rebase-segments"
            let entries: [ScriptValue]
            do { entries = try WorkspaceScriptingAPI.segmentEditBatchEntries(arguments, rebasing: rebasing) }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
            for (index, entry) in entries.enumerated() {
                do { try validateDiagnosed(command: rebasing ? "rebase-segment" : "rename-segment", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let field = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: field, code: refusal.code, detail: "\(field): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "set-tags", "set-colors":
            let field = command == "set-tags" ? "tag" : "color"
            guard Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
                throw ToolArgumentError(field: "entries", detail: "Expected 1–1024 entries only.")
            }
            var seen = Set<UInt64>()
            for (index, entry) in entries.enumerated() {
                guard case .object(let row) = entry, Set(row.keys) == ["address", field], let address = row["address"]?.addressValue,
                      row[field]?.stringValue != nil else {
                    throw ToolArgumentError(field: "entries[\(index)]", detail: "Entry must contain an address and \(field) string only.")
                }
                guard seen.insert(address).inserted else { throw ToolArgumentError(field: "entries[\(index)].address", detail: "Duplicate address.") }
                if field == "color", let text = row[field]?.stringValue, !text.isEmpty, ColorTag(rawValue: text) == nil {
                    throw ToolArgumentError(field: "entries[\(index)].color", detail: "Invalid color.", allowed: [""] + ColorTag.allCases.map(\.rawValue))
                }
                do { try validateDiagnosed(command: command == "set-tags" ? "set-tag" : "set-color", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let path = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: path, code: refusal.code, detail: "\(path): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "add-xrefs", "suppress-xrefs":
            let entries: [ScriptValue]
            do { entries = try WorkspaceScriptingAPI.manualXRefBatchEntries(arguments) }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
            for (index, entry) in entries.enumerated() {
                do { try validateDiagnosed(command: command == "add-xrefs" ? "add-xref" : "suppress-xref", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let field = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: field, code: refusal.code, detail: "\(field): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "add-bookmarks", "remove-bookmarks":
            let removing = command == "remove-bookmarks"
            let entries: [ScriptValue]
            do { entries = try WorkspaceScriptingAPI.bookmarkBatchEntries(arguments, removing: removing) }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
            for (index, entry) in entries.enumerated() {
                do { try validateDiagnosed(command: removing ? "remove-bookmark" : "add-bookmark", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let field = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: field, code: refusal.code, detail: "\(field): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "set-stack-locals":
            let entries: [ScriptValue]
            do { entries = try WorkspaceScriptingAPI.stackLocalBatchEntries(arguments) }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
            for (index, entry) in entries.enumerated() {
                do { try validateDiagnosed(command: "set-stack-local", arguments: entry) }
                catch let error as ToolArgumentError {
                    let refusal = error.refusal
                    let suffix = refusal.field.map { $0 == "arguments" ? "" : "." + $0 } ?? ""
                    let field = "entries[\(index)]" + suffix
                    throw ToolArgumentError(field: field, code: refusal.code, detail: "\(field): \(refusal.detail)", expected: refusal.expected, allowed: refusal.allowed, minimum: refusal.minimum, maximum: refusal.maximum, underlying: error.underlying)
                }
            }
        case "clear-segment-overrides":
            do { _ = try WorkspaceScriptingAPI.clearSegmentOverrideEntries(arguments) }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                throw ToolArgumentError(field: String(detail.prefix { $0 != ":" }), detail: detail, underlying: .scripting(error))
            }
        case "set-names", "set-comments", "set-local-labels", "set-operand-formats", "set-types":
            let textField = command == "set-names" ? "name" : (command == "set-local-labels" ? "label" : (command == "set-operand-formats" ? "format" : (command == "set-types" ? "type" : "comment")))
            guard let entries = fields["entries"]?.arrayValue else {
                throw ToolArgumentError(field: "entries[0]", detail: "Entry 0: 'entries' must be an array.",
                                        expected: "array")
            }
            guard !entries.isEmpty else {
                throw ToolArgumentError(field: "entries[0]", code: .outOfBounds,
                                        detail: "Entry 0 is required.", minimum: 1)
            }
            guard entries.count <= 1024 else {
                throw ToolArgumentError(field: "entries[1024]", code: .outOfBounds,
                                        detail: "Entry 1024 exceeds the 1024-entry batch limit.", maximum: 1024)
            }
            var seen: Set<UInt64> = []
            for (index, item) in entries.enumerated() {
                let label = "entries[\(index)]"
                guard case .object(let entry) = item, Set(entry.keys) == ["address", textField] else {
                    throw ToolArgumentError(field: label,
                        detail: "Entry \(index) must contain address and \(textField) only.",
                        expected: "object", allowed: ["address", textField])
                }
                guard let address = entry["address"]?.addressValue else {
                    throw ToolArgumentError(field: label + ".address",
                        detail: "Entry \(index) has an invalid address.", expected: "address string or non-negative integer")
                }
                guard entry[textField]?.stringValue != nil else {
                    throw ToolArgumentError(field: label + "." + textField,
                        detail: "Entry \(index) field '\(textField)' must be a string.", expected: "string")
                }
                if command == "set-operand-formats", let format = entry[textField]?.stringValue,
                   !format.isEmpty, OperandFormat(rawValue: format) == nil {
                    throw ToolArgumentError(field: label + ".format", detail: "Entry \(index) has an invalid operand format.",
                                            allowed: [""] + OperandFormat.allCases.map(\.rawValue))
                }
                guard seen.insert(address).inserted else {
                    throw ToolArgumentError(field: label + ".address",
                        detail: "Entry \(index) repeats an address.")
                }
            }
        case "verified-commit": try WorkspaceScriptingAPI.verifiedCommitValidate(fields)
        case "verified-checkpoint-isolated": try WorkspaceScriptingAPI.verifiedCheckpointIsolatedValidate(fields)
        case "open-workspace", "save-workspace":
            try string("path", maximum: 4_096)
        case "info":
            try validateOptionalInteger(fields["waitForReadyMs"], range: 0...25_000, field: "waitForReadyMs")
        case "decompile":
            do {
                _ = try WorkspaceScriptingAPI.decompileBackendChoice(arguments)
                _ = try WorkspaceScriptingAPI.decompileShape(arguments)
                _ = try WorkspaceScriptingAPI.decompileFold(arguments)
            }
            catch let error as ScriptingError {
                guard case .invalidArgument(let detail) = error else { throw error }
                let field = detail.hasPrefix("fold") ? "fold" : detail.hasPrefix("backend") ? "backend" : (detail.hasPrefix("format") ? "format" : (detail.hasPrefix("lineRange") ? "lineRange" : "cursor"))
                throw ToolArgumentError(field: field, detail: detail, underlying: .scripting(error))
            }
        case "add-xref", "suppress-xref":
            if let raw = fields["kind"], raw != .null,
               raw.stringValue.map({ xrefKinds.contains($0) }) != true {
                throw ToolArgumentError(field: "kind", detail: "Field 'kind' must be call, string, selref, classref or data.",
                    expected: "string", allowed: xrefKinds.sorted())
            }
        case "callers", "implementations":
            if let value = fields["selector"], value != .null {
                try string("selector", maximum: 1_024)
                if value.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true {
                    throw ToolArgumentError(field: "selector", detail: "Field 'selector' must not be empty.", expected: "string")
                }
                if command == "callers",
                   (fields["function"].map { $0 != .null } ?? false) || (fields["address"].map { $0 != .null } ?? false) {
                    throw ToolArgumentError(field: "selector", detail: "Field 'selector' cannot be combined with 'function' or 'address'.")
                }
            } else if command == "implementations" {
                throw ToolArgumentError(field: "selector", detail: "Field 'selector' is required.", expected: "string")
            }
            if command == "callers", let value = fields["selectors"], value != .null {
                guard case .array(let items) = value else {
                    throw ToolArgumentError(field: "selectors", detail: "Field 'selectors' must be an array of strings.", expected: "array")
                }
                guard (1...8).contains(items.count) else {
                    throw ToolArgumentError(field: "selectors", code: .outOfBounds,
                        detail: "Field 'selectors' must contain 1 to 8 entries.", minimum: 1, maximum: 8)
                }
                var distinct = Set<String>()
                for item in items {
                    guard let text = item.stringValue else {
                        throw ToolArgumentError(field: "selectors", detail: "Field 'selectors' entries must be strings.", expected: "string")
                    }
                    if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        throw ToolArgumentError(field: "selectors", detail: "Field 'selectors' entries must not be empty.", expected: "string")
                    }
                    if text.utf8.count > 1_024 {
                        throw ToolArgumentError(field: "selectors", code: .outOfBounds,
                            detail: "Field 'selectors' entries must contain at most 1024 UTF-8 bytes.", maximum: 1_024)
                    }
                    if !distinct.insert(text).inserted {
                        throw ToolArgumentError(field: "selectors", detail: "Field 'selectors' entries must be distinct.")
                    }
                }
                for key in ["selector", "function", "address"] {
                    if let other = fields[key], other != .null {
                        throw ToolArgumentError(field: "selectors",
                            detail: "Field 'selectors' cannot be combined with 'selector', 'function' or 'address'.")
                    }
                }
            }
        default: break
        }
    }

    /// Transport default only: direct authority/CLI/attached calls retain legacy output.
    static func decompileMCPArguments(command: String, arguments: ScriptValue) -> ScriptValue {
        guard command == "decompile", case .object(var fields) = arguments,
              fields["format"] == nil || fields["format"] == .null else { return arguments }
        fields["format"] = .string("text")
        return .object(fields)
    }

    static func execute(
        command: String,
        arguments: ScriptValue,
        api: WorkspaceScriptingAPI,
        proposingPrincipal: Phase2Principal = .human
    ) throws -> ScriptValue {
        MCPFatalSignalReporter.prepareAlternateStack()
        try validate(command: command, arguments: arguments)
        ScriptingGenerationCapture.current?.record(api.store.snapshot.analysisGenerationID)
        if NavigatorMCPCommands.handles(command) {
            return try NavigatorMCPCommands.execute(command: command, arguments: arguments, surface: .live(api.store))
        }
        if let refusal = searchRefusal(command: command, arguments: arguments) { return refusal }
        guard command == "commands" else {
            return try api.execute(command, arguments: arguments, proposingPrincipal: proposingPrincipal,
                                   validateDirectHex: false)
        }
        ScriptingGenerationCapture.current?.record(api.store.snapshot.analysisGenerationID)
        return .array(catalogSnapshot.commands.map { info in
            .object([
                "name": .string(info.name),
                "summary": .string(info.summary),
                "mutates": .bool(info.mutates),
                "arguments": .array(info.arguments.map(ScriptValue.string)),
            ])
        })
    }

    /// Default async transport uses the same closed command/argument authority and principal.
    /// The catalog command retains the headless filtered catalog rather than exposing API-only tools.
    static func executeAsync(
        command: String,
        arguments: ScriptValue,
        api: WorkspaceScriptingAPI,
        proposingPrincipal: Phase2Principal = .human
    ) async throws -> ScriptValue {
        try await executeAsyncAnnotated(command: command, arguments: arguments, api: api,
            proposingPrincipal: proposingPrincipal, collectDispatchNote: false).result
    }

    static func executeAsyncAnnotated(
        command: String,
        arguments: ScriptValue,
        api: WorkspaceScriptingAPI,
        proposingPrincipal: Phase2Principal = .human,
        collectDispatchNote: Bool = true
    ) async throws -> ScriptingAnnotatedResult {
        MCPFatalSignalReporter.prepareAlternateStack()
        try validate(command: command, arguments: arguments)
        ScriptingGenerationCapture.current?.record(api.store.snapshot.analysisGenerationID)
        if NavigatorMCPCommands.handles(command) {
            return ScriptingAnnotatedResult(result: try await NavigatorMCPCommands.executeAsync(
                command: command, arguments: arguments, surface: .live(api.store)))
        }
        if let refusal = searchRefusal(command: command, arguments: arguments) {
            return ScriptingAnnotatedResult(result: refusal)
        }
        if command == "commands" {
            return ScriptingAnnotatedResult(result: try execute(command: command, arguments: arguments, api: api,
                proposingPrincipal: proposingPrincipal))
        }
        return try await api.executeAsyncAnnotated(command, arguments: arguments,
            proposingPrincipal: proposingPrincipal, collectDispatchNote: collectDispatchNote,
            validateDirectHex: false)
    }

    /// Typed refusals for `search` that must never read as an empty result (DEF-A03, DEF-A09).
    /// Returned as an ordinary result value `{error, detail}` after `validate`, so inline, async
    /// and attached transports answer identically and the engine's own cap is never reached:
    /// - a query over `maximumSearchQueryBytes` (measured on the trimmed query, as the engine
    ///   does) is `invalidPattern` with detail `tooLong`;
    /// - a regex-mode query that does not compile is `invalidPattern` with the compiler's message.
    /// Text and hex modes are unchanged: an unparseable hex pattern still searches to no rows.
    static func searchRefusal(command: String, arguments: ScriptValue) -> ScriptValue? {
        guard command == "search", case .object(let fields) = arguments,
              let query = fields["query"]?.stringValue else { return nil }
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard needle.utf8.count <= maximumSearchQueryBytes else {
            return invalidPatternRefusal(detail: "tooLong")
        }
        let mode = fields["mode"]?.stringValue.flatMap(BinarySearchMode.init(rawValue:))
        guard mode == .regex, let message = BinarySearchService().validate(query: needle, mode: .regex) else {
            return nil
        }
        return invalidPatternRefusal(detail: message)
    }

    private static func invalidPatternRefusal(detail: String) -> ScriptValue {
        .object(["error": .string("invalidPattern"), "detail": .string(detail)])
    }

    private static func validateOptionalInteger(
        _ value: ScriptValue?, range: ClosedRange<Int64>, field: String
    ) throws {
        guard let value else { return }
        guard case .int(let integer) = value else {
            throw ToolArgumentError(field: field, detail: "Field '\(field)' must be an integer.", expected: "integer")
        }
        guard range.contains(integer) else {
            throw ToolArgumentError(field: field, code: .outOfBounds,
                detail: "Field '\(field)' must be between \(range.lowerBound) and \(range.upperBound).",
                minimum: range.lowerBound, maximum: range.upperBound)
        }
    }

    private static func validateOptionalBool(_ value: ScriptValue?, field: String) throws {
        guard let value else { return }
        guard value.boolValue != nil else {
            throw ToolArgumentError(field: field, detail: "Field '\(field)' must be a boolean.", expected: "boolean")
        }
    }

    private static func validateValue(_ value: ScriptValue, depth: Int, field: String) throws {
        guard depth <= 16 else {
            throw ToolArgumentError(field: field, code: .outOfBounds,
                detail: "Field '\(field)' exceeds nesting depth 16.", maximum: 16)
        }
        switch value {
        case .string(let value):
            guard value.utf8.count <= maximumArgumentStringBytes else {
                throw ToolArgumentError(field: field, code: .outOfBounds,
                    detail: "Field '\(field)' exceeds \(maximumArgumentStringBytes) UTF-8 bytes.",
                    maximum: Int64(maximumArgumentStringBytes))
            }
        case .array(let values):
            guard values.count <= maximumContainerMembers else {
                throw ToolArgumentError(field: field, code: .outOfBounds,
                    detail: "Field '\(field)' exceeds \(maximumContainerMembers) members.",
                    maximum: Int64(maximumContainerMembers))
            }
            for value in values { try validateValue(value, depth: depth + 1, field: field) }
        case .object(let fields):
            guard fields.count <= maximumContainerMembers else {
                throw ToolArgumentError(field: field, code: .outOfBounds,
                    detail: "Field '\(field)' exceeds \(maximumContainerMembers) members.",
                    maximum: Int64(maximumContainerMembers))
            }
            for key in fields.keys.sorted() {
                guard !key.isEmpty else {
                    throw ToolArgumentError(field: field, detail: "Field '\(field)' contains an empty object key.",
                                            expected: "non-empty object keys")
                }
                guard key.utf8.count <= 256 else {
                    throw ToolArgumentError(field: field, code: .outOfBounds,
                        detail: "Field '\(field)' contains an object key longer than 256 UTF-8 bytes.", maximum: 256)
                }
                if let value = fields[key] {
                    try validateValue(value, depth: depth + 1, field: depth == 0 ? key : field)
                }
            }
        case .double(let number):
            guard number.isFinite else {
                throw ToolArgumentError(field: field, detail: "Field '\(field)' must contain finite numbers.",
                                        expected: "finite number")
            }
        case .null, .bool, .int: break
        }
    }
}

enum HeadlessProtocolIOError: LocalizedError {
    case descriptorFailure
    case writeFailure

    var errorDescription: String? {
        switch self {
        case .descriptorFailure: "Could not isolate the headless protocol output descriptor."
        case .writeFailure: "Could not write the complete headless protocol response."
        }
    }
}

/// Captures the original stdout descriptor, then sends every incidental `print` or library log
/// to `/dev/null`. Protocol bytes are written only through the captured descriptor.
enum HeadlessProtocolIO {
    static func isolateStandardOutput() throws -> FileHandle {
        signal(SIGPIPE, SIG_IGN)
        let replacement = open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard replacement >= 0 else { throw HeadlessProtocolIOError.descriptorFailure }
        defer { close(replacement) }
        return try isolate(outputDescriptor: STDOUT_FILENO, replacingWith: replacement)
    }

    static func isolate(
        outputDescriptor: Int32, replacingWith replacementDescriptor: Int32
    ) throws -> FileHandle {
        let protocolDescriptor = dup(outputDescriptor)
        guard protocolDescriptor >= 0 else { throw HeadlessProtocolIOError.descriptorFailure }
        let descriptorFlags = fcntl(protocolDescriptor, F_GETFD)
        guard descriptorFlags >= 0,
              fcntl(protocolDescriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0,
              dup2(replacementDescriptor, outputDescriptor) >= 0 else {
            close(protocolDescriptor)
            throw HeadlessProtocolIOError.descriptorFailure
        }
        return FileHandle(fileDescriptor: protocolDescriptor, closeOnDealloc: true)
    }

    static func writeLine(_ data: Data, to output: FileHandle) throws {
        try write(data, to: output)
        try write(Data([0x0A]), to: output)
    }

    static func write(_ data: Data, to output: FileHandle) throws {
        var written = 0
        try data.withUnsafeBytes { bytes in
            while written < bytes.count {
                let result = Darwin.write(
                    output.fileDescriptor,
                    bytes.baseAddress?.advanced(by: written),
                    bytes.count - written
                )
                if result < 0, errno == EINTR { continue }
                guard result > 0 else { throw HeadlessProtocolIOError.writeFailure }
                written += result
            }
        }
    }
}

/// A Model Context Protocol (JSON-RPC 2.0) server over the scripting command surface.
/// The protocol handler is request-in/response-out; `runStdioLoop` is the bounded NDJSON
/// transport. One server instance owns one API/store and one cancellation ledger.
@MainActor
struct MCPServer {
    struct Configuration: Sendable {
        static let production = Configuration(
            maximumInputBytes: 1 * 1_024 * 1_024,
            maximumOutputBytes: 8 * 1_024 * 1_024,
            maximumToolDurationNanoseconds: 30 * 1_000_000_000,
            maximumRememberedCancellations: 1_024
        )

        let maximumInputBytes: Int
        let maximumOutputBytes: Int
        let maximumToolDurationNanoseconds: UInt64
        let maximumRememberedCancellations: Int
        let maximumInFlightRequests: Int
        let listingProfile: MCPToolListingProfile?

        init(
            maximumInputBytes: Int,
            maximumOutputBytes: Int,
            maximumToolDurationNanoseconds: UInt64,
            maximumRememberedCancellations: Int,
            maximumInFlightRequests: Int = 64,
            listingProfile: MCPToolListingProfile? = nil
        ) {
            precondition(maximumInputBytes > 0)
            precondition(maximumOutputBytes >= 512)
            precondition(maximumToolDurationNanoseconds > 0)
            precondition(maximumRememberedCancellations > 0)
            precondition(maximumInFlightRequests > 0 && maximumInFlightRequests <= 1_024)
            self.maximumInputBytes = maximumInputBytes
            self.maximumOutputBytes = maximumOutputBytes
            self.maximumToolDurationNanoseconds = maximumToolDurationNanoseconds
            self.maximumRememberedCancellations = maximumRememberedCancellations
            self.maximumInFlightRequests = maximumInFlightRequests
            self.listingProfile = listingProfile
        }
    }

    static let protocolVersion = "2024-11-05"
    static let serverName = "macscope"
    static let serverVersion = "0.1.0"

    static let sessionInstructions = """
    MacScope MCP server for one Mach-O binary that is already open; there is no open-file step.
    While analysis runs, tools reply notReady; call info (waitForReadyMs from 0 to 25000 waits) until it reports ready.
    Addresses are hex strings such as "0x100003f20", in arguments and in replies.
    Evidence: each completed workspace read appends a text block {generation: UUID} and returns _meta.generation. The first content block keeps its legacy shape. Pass that UUID as optional basedOnGeneration on a write; staleEvidence names basedOnGeneration and currentGeneration without applying the write. Successful writes return the resulting generation; changed annotations can advance it even without reanalysis, so chain the new reply generation or read again. Navigator staleCursor is unchanged.
    Start with info, then list-image-types (classes, categories, protocols, Swift types) or search (mode text, regex or hex), then decompile a function by name or address.
    Graph: callers, callees and xrefs; callers of an _objc_msgSend$<selector> stub lists that selector's call sites.
    Names: name-at, functions, symbols and strings; demangle renders one Swift mangled name.
    Images: search, callers, callees and xrefs rows carry imageSlot; imageSlot or image selects one loaded image; without it, search reads every loaded image and other tools read the primary image.
    Limits depend on image size: large scans and results stop at a budget and say so (a refusal or isTruncated); narrow with limit, kind, imageSlot or a search cursor and retry; a list-image-types explicit limit is still subject to its byte allowance, so continue a default nextCursor as cursor with page:true, fields:"full", limit:1 and the original image/kind.
    Type Atlas: list-image-types total is the whole-filter total and types.count is the admitted default prefix; an explicit limit is additionally byte-capped, and unnamed vtable slots may be summarized as unnamedVtableSlots with vtableSummaryVersion 1. When isTruncated, pass nextCursor as cursor with page:true, fields:"full", limit:1 and the original image/kind. For browsing use page:true, fields:"names" (kind, name or nameContains narrow it); a full-detail page does not carry the default reply's 180,000-byte bound.
    Tools whose description ends "(mutates the workspace)" change workspace state, for example names, comments, types, code/data markup, xrefs, patches, bookmarks, segments, navigation, undo or the open workspace; every other tool is read-only.
    Groups: reads (info, functions, symbols, strings, sections, search, decompile, instructions, read-bytes), graph (callers, callees, xrefs, open-claim, record-callee-outcome, claim-status), types (list-image-types, list-types), edits (the mutating tools), navigator-* (evidence navigator); commands lists the scripting commands.
    """

    private let startup: MCPStartupGate?
    private let fixedAPI: WorkspaceScriptingAPI?
    var api: WorkspaceScriptingAPI? { fixedAPI ?? startup?.api }
    private let configuration: Configuration
    private let monotonicNow: @MainActor () -> UInt64
    private let validateWorkspaceIdentity: @MainActor () throws -> Void
    typealias AsyncCommandExecutor = @MainActor @Sendable (String, ScriptValue) async throws -> ScriptValue
    private let asyncCommandExecutor: AsyncCommandExecutor?
    /// When set (MCP attach), the only tools listed and dispatched; others are unavailable.
    private let allowedCommands: Set<String>?
    private let listHarnessTools: Bool
    private let session: SessionState
    /// Opt-in request timing; disabled (a no-op) unless the launcher selects it.
    var timing = MCPRequestTiming.disabled

    init(
        api: WorkspaceScriptingAPI,
        configuration: Configuration = .production,
        monotonicNow: @escaping @MainActor () -> UInt64 = {
            DispatchTime.now().uptimeNanoseconds
        },
        validateWorkspaceIdentity: @escaping @MainActor () throws -> Void = {},
        asyncCommandExecutor: AsyncCommandExecutor? = nil,
        allowedCommands: Set<String>? = nil,
        listHarnessTools: Bool = ProcessInfo.processInfo.environment["MACSCOPE_MCP_HARNESS_TOOLS"] == "1"
    ) {
        self.fixedAPI = api
        self.startup = nil
        self.asyncCommandExecutor = asyncCommandExecutor
        self.allowedCommands = allowedCommands
        self.listHarnessTools = listHarnessTools
        self.configuration = configuration
        self.monotonicNow = monotonicNow
        self.validateWorkspaceIdentity = validateWorkspaceIdentity
        session = SessionState(maximumCancellations: configuration.maximumRememberedCancellations)
    }

    init(
        startup: MCPStartupGate,
        configuration: Configuration = .production,
        monotonicNow: @escaping @MainActor () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        listHarnessTools: Bool = ProcessInfo.processInfo.environment["MACSCOPE_MCP_HARNESS_TOOLS"] == "1"
    ) {
        self.fixedAPI = nil
        self.startup = startup
        self.asyncCommandExecutor = nil
        self.allowedCommands = nil
        self.listHarnessTools = listHarnessTools
        self.configuration = configuration
        self.monotonicNow = monotonicNow
        self.validateWorkspaceIdentity = { try startup.validateIdentity() }
        session = SessionState(maximumCancellations: configuration.maximumRememberedCancellations)
    }

    // MARK: - JSON-RPC handling

    /// Handles exactly one decoded JSON-RPC request. A valid notification executes but never
    /// receives a response; an invalid request always receives an Invalid Request response.
    func handle(_ request: ScriptValue) -> ScriptValue? {
        let fence = MCPExecutionFence.connection ?? session.fence
        let outcome = MCPExecutionFence.outcome ?? MCPMutationOutcome()
        return MCPExecutionFence.$connection.withValue(fence) {
            MCPExecutionFence.$outcome.withValue(outcome) {
                guard !fence.isFailed else { return nil }
                return handleAdmitted(request)
            }
        }
    }

    private func handleAdmitted(_ request: ScriptValue) -> ScriptValue? {
        guard case .object(let fields) = request else {
            return error(nil, -32600, "Invalid Request")
        }
        let idIsPresent = fields.keys.contains("id")
        let id = fields["id"]
        guard validResponseID(id, isPresent: idIsPresent) else {
            return error(nil, -32600, "Invalid Request")
        }
        let isNotification = !idIsPresent
        guard fields["jsonrpc"]?.stringValue == "2.0",
              let method = fields["method"]?.stringValue,
              !method.isEmpty,
              method.utf8.count <= 256,
              !method.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            return error(id, -32600, "Invalid Request")
        }

        let response: ScriptValue?
        switch method {
        case "initialize":
            guard validObjectParams(fields["params"]) else {
                response = error(id, -32602, "Invalid params",
                    terminal: .invalidParams(field: "params", expected: "object"))
                break
            }
            let version = session.negotiate(fields["params"]?["protocolVersion"])
            response = result(id, initializeResult(version))
        case "ping":
            guard validObjectParams(fields["params"]) else {
                response = error(id, -32602, "Invalid params",
                    terminal: .invalidParams(field: "params", expected: "object"))
                break
            }
            response = result(id, .object([:]))
        case "tools/list":
            guard validObjectParams(fields["params"]) else {
                response = error(id, -32602, "Invalid params",
                    terminal: .invalidParams(field: "params", expected: "object"))
                break
            }
            response = result(id, toolsListResult())
        case "tools/call":
            response = toolsCall(id: id, requestKey: requestKey(id), params: fields["params"])
        case "notifications/cancelled":
            guard isNotification else {
                return error(id, -32600, "Invalid Request")
            }
            recordCancellation(fields["params"])
            return nil
        case let name where name.hasPrefix("notifications/"):
            return isNotification ? nil : error(id, -32601, "Method not found")
        default:
            response = error(id, -32601, "Method not found")
        }
        return isNotification ? nil : response
    }

    /// Strictly parses one message and returns one bounded response, or nil for a valid
    /// notification/blank line.
    func handleMessage(_ data: Data) -> Data? {
        let fence = MCPExecutionFence.connection ?? session.fence
        let outcome = MCPExecutionFence.outcome ?? MCPMutationOutcome()
        return MCPExecutionFence.$connection.withValue(fence) {
            MCPExecutionFence.$outcome.withValue(outcome) {
                guard !fence.isFailed else { return nil }
                return handleMessageAdmitted(data)
            }
        }
    }

    private func handleMessageAdmitted(_ data: Data) -> Data? {
        guard !data.allSatisfy(Self.isJSONWhitespace) else { return nil }
        guard data.count <= configuration.maximumInputBytes else {
            return encodeBounded(error(nil, -32700, "Parse error"))
        }
        let frame: MCPAdmittedFrame
        let request: ScriptValue
        do {
            frame = try timing.measure(.admit) {
                try MCPAdmittedFrame.admit(data, maximumBytes: configuration.maximumInputBytes)
            }
            request = try timing.measure(.decode) { try frame.legacyValue() }
        } catch {
            return encodeBounded(self.error(nil, -32700, "Parse error"))
        }
        let refusal = batchReceiptRefusal(request, frame: frame)
        if refusal.refused { return refusal.response }
        guard let response = timing.measure(.dispatch, { handle(request) }) else { return nil }
        return timing.measure(.encode) {
            encodeBounded(response, restoringID: originalID(from: frame, request: request))
        }
    }

    private func batchReceiptRefusal(_ request: ScriptValue, frame: MCPAdmittedFrame) -> (refused: Bool, response: Data?) {
        guard case .object(let fields) = request, fields.keys.contains("id"),
              fields["jsonrpc"]?.stringValue == "2.0",
              fields["method"]?.stringValue == "tools/call",
              let name = fields["params"]?["name"]?.stringValue,
              MCPBatchReceiptBudget.commands.contains(name),
              let original = originalID(from: frame, request: request),
              !MCPBatchReceiptBudget.admits(idBytes: original.canonicalJSONBytes().count,
                                            maximumBytes: configuration.maximumOutputBytes) else { return (false, nil) }
        do {
            return (true, try MCPBatchReceiptBudget.refusalFrame(id: original, maximumBytes: configuration.maximumOutputBytes))
        } catch {
            (MCPExecutionFence.connection ?? session.fence).fail()
            return (true, nil)
        }
    }

    private func originalID(from frame: MCPAdmittedFrame, request: ScriptValue) -> Phase2ProductionJSONValue? {
        guard case .object(let fields) = request, fields.keys.contains("id"),
              validResponseID(fields["id"], isPresent: true) else { return nil }
        return frame.originalID
    }

    func handleLine(_ line: String) -> String? {
        guard let response = handleMessage(Data(line.utf8)) else { return nil }
        return String(data: response, encoding: .utf8)
    }

    /// Bounded newline-delimited JSON transport. Oversized lines are drained through their
    /// delimiter, receive one parse error, and cannot desynchronize the following request.
    func runStdioLoop(
        input: FileHandle = .standardInput,
        output: FileHandle = .standardOutput
    ) {
        let reader = BoundedLineReader(
            descriptor: input.fileDescriptor,
            maximumLineBytes: configuration.maximumInputBytes
        )
        while !session.fence.isFailed {
            let event: BoundedLineReader.Event
            do {
                event = try reader.next()
            } catch {
                return
            }
            let response: Data?
            switch event {
            case .message(let data):
                response = handleMessage(data)
            case .oversized:
                response = encodeBounded(error(nil, -32700, "Parse error"))
            case .end:
                return
            }
            guard !session.fence.isFailed else { return }
            guard let response else { continue }
            do {
                guard MCPFrameAdmission.fits(response, maximumBytes: configuration.maximumOutputBytes) else {
                    throw MCPFrameAdmission.Failure.unrepresentable
                }
                try session.fence.admit { try HeadlessProtocolIO.writeLine(response, to: output) }
            } catch {
                session.fence.fail()
                return
            }
        }
    }

    // MARK: - Method results

    private func initializeResult(_ version: MCPResultProtocol) -> ScriptValue {
        var capabilities: [String: ScriptValue] = ["tools": .object([:])]
        if let startup { capabilities["experimental"] = .object(["macscope/analysis": startup.analysisValue()]) }
        return .object([
            "protocolVersion": .string(version.rawValue),
            "instructions": .string(Self.sessionInstructions + MCPToolsListCompaction.instructionSupplement(for: configuration.listingProfile) + version.instructionSuffix),
            "capabilities": .object(capabilities),
            "serverInfo": .object(["name": .string(Self.serverName), "version": .string(Self.serverVersion)]),
        ])
    }

    private func startupReply(_ id: ScriptValue?, name: String,
                              protocolVersion: MCPResultProtocol) -> ScriptValue? {
        guard let startup, startup.status.snapshot().state != "ready" else { return nil }
        let analysis = startup.analysisValue()
        let payload: ScriptValue
        if name == "info" {
            payload = .object(["analysis": analysis])
        } else {
            guard case .object(var fields) = analysis else { return nil }
            fields["error"] = .string(fields["state"] == .string("failed") ? "analysisFailed" : "notReady")
            payload = .object(fields)
        }
        let data: Data
        do { data = try payload.jsonData() }
        catch { return self.error(id, -32603, "Response exceeds limit", terminal: .encoding) }
        guard data.count <= configuration.maximumOutputBytes / 2 else {
            return error(id, -32603, "Response exceeds limit", terminal: .output(
                limit: configuration.maximumOutputBytes / 2, used: data.count))
        }
        guard let text = String(data: data, encoding: .utf8) else {
            return error(id, -32603, "Response exceeds limit", terminal: .encoding)
        }
        return result(id, MCPStructuredResult.successEnvelope(
            protocolVersion: protocolVersion, tool: name, output: payload,
            legacyText: text, isError: name != "info"))
    }

    private func withStartupAnalysis(_ name: String, _ output: ScriptValue) -> ScriptValue {
        guard name == "info", let startup, case .object(var fields) = output else { return output }
        fields["analysis"] = startup.analysisValue()
        return .object(fields)
    }

    private func toolsListResult() -> ScriptValue {
        .object(["tools": .array(HeadlessAutomationAuthority.catalogSnapshot.commands.filter {
            (allowedCommands?.contains($0.name) ?? true)
                && (listHarnessTools || !HeadlessAutomationAuthority.harnessCommands.contains($0.name))
                && (configuration.listingProfile?.lists($0.name, harnessVisible: listHarnessTools) ?? true)
        }.map { command -> ScriptValue in
            return .object([
                "name": .string(command.name),
                "description": .string(command.summary + (command.mutates ? " (mutates the workspace)" : "")),
                "inputSchema": HeadlessAutomationAuthority.inputSchema(for: command),
                "annotations": .object([
                    "readOnlyHint": .bool(!command.mutates),
                    "destructiveHint": .bool(command.mutates),
                ]),
            ])
        }.map { (entry: ScriptValue) -> ScriptValue in
            MCPToolsListCompaction.entry(entry, profile: configuration.listingProfile)
        })])
    }

    /// The production transport owns cancellation outside MainActor. Commands still
    /// enter the same closed authority, workspace identity and principal boundary.
    func makeRequestSession(fence: MCPConnectionFence = MCPConnectionFence(),
                            output: @escaping @Sendable (Data) async throws -> Void) -> MCPRequestSession {
        MCPRequestSession(configuration: configuration,
            mutatingCommands: timing.measure(.catalogBuild) { HeadlessAutomationAuthority.catalogSnapshot.mutatingNames },
            execute: { data in await handleMessageAsync(data) }, output: output, fence: fence,
            progressSource: startup?.status)
    }

    func handleMessageAsync(_ data: Data) async -> Data? {
        let fence = MCPExecutionFence.connection ?? session.fence
        let outcome = MCPExecutionFence.outcome ?? MCPMutationOutcome()
        return await MCPExecutionFence.$connection.withValue(fence) {
            await MCPExecutionFence.$outcome.withValue(outcome) {
                guard !fence.isFailed else { return nil }
                return await handleMessageAsyncAdmitted(data)
            }
        }
    }

    private func handleMessageAsyncAdmitted(_ data: Data) async -> Data? {
        guard let frame = try? timing.measure(.admit, {
                  try MCPAdmittedFrame.admit(data, maximumBytes: configuration.maximumInputBytes)
              }),
              let request = try? timing.measure(.decode, { try frame.legacyValue() }),
              case .object(let fields) = request,
              fields["jsonrpc"]?.stringValue == "2.0",
              fields["method"]?.stringValue == "tools/call",
              validResponseID(fields["id"], isPresent: fields.keys.contains("id")) else {
            return handleMessage(data)
        }
        let refusal = batchReceiptRefusal(request, frame: frame)
        if refusal.refused { return refusal.response }
        let response = await timing.measure(.dispatch) {
            await toolsCallAsync(id: fields["id"], requestKey: nil, params: fields["params"])
        }
        return fields.keys.contains("id")
            ? timing.measure(.encode) { encodeBounded(response, restoringID: originalID(from: frame, request: request)) }
            : nil
    }

    /// Blocking reads live on a detached transport task; provider suspension or a busy
    /// MainActor cannot prevent that task from cancelling the exact in-flight operation.
    func runStdioLoopAsync(input: FileHandle = .standardInput,
                           output: FileHandle = .standardOutput) async {
        MCPFatalSignalReporter.prepareAlternateStack()
        let reader = BoundedLineReader(descriptor: input.fileDescriptor,
                                       maximumLineBytes: configuration.maximumInputBytes)
        let fence = MCPConnectionFence(onFailure: { reader.stop() })
        let writer = MCPResponseWriter(output: output, maximumBytes: configuration.maximumOutputBytes, fence: fence)
        let writeTiming = timing  // @Sendable closure captures a Sendable local copy, not self
        let requests = makeRequestSession(fence: fence, output: { data in
            do { try await writeTiming.measure(.write) { try await writer.write(data) } }
            catch { reader.stop(); throw error }
        })
        await Task.detached {
            do {
                while true {
                    MCPFatalSignalReporter.prepareAlternateStack()
                    switch try reader.next() {
                    case .message(let data): await requests.receive(data)
                    case .oversized: await requests.receiveOversized()
                    case .end:
                        await requests.finishInput()
                        return
                    }
                }
            } catch {
                await requests.finishInput()
            }
        }.value
    }

    private func toolsCallAsync(
        id: ScriptValue?, requestKey: RequestKey?, params: ScriptValue?
    ) async -> ScriptValue {
        // Capture before validation, startup waits, execution or off-actor encoding can suspend.
        let protocolVersion = session.resultProtocol
        guard case .some(.object(let fields)) = params,
              Set(fields.keys).isSubset(of: ["name", "arguments", "_meta"]),
              let name = fields["name"]?.stringValue,
              !name.isEmpty,
              name.utf8.count <= 256,
              !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            return error(id, -32602, "Invalid params",
                terminal: .invalidParams(field: nil, expected: nil))
        }
        if let metadata = fields["_meta"], case .object = metadata {
            // Metadata is admitted only as an object and is deliberately not forwarded.
        } else if fields["_meta"] != nil {
            return error(id, -32602, "Invalid params",
                terminal: .invalidParams(field: "params._meta", expected: "object"))
        }
        let arguments: ScriptValue
        switch fields["arguments"] {
        case .none, .some(.null):
            arguments = .object([:])
        case .some(let value):
            guard case .object = value else {
                return error(id, -32602, "Invalid params",
                    terminal: .invalidParams(field: "params.arguments", expected: "object or null"))
            }
            arguments = value
        }
        if let allowedCommands, !allowedCommands.contains(name) {
            return toolFailure(id, "Tool is unavailable through headless automation.")
        }
        if MCPBatchReceiptBudget.commands.contains(name) {
            guard let encodedID = try? (id ?? .null).jsonData(),
                  MCPBatchReceiptBudget.admits(idBytes: encodedID.count, maximumBytes: configuration.maximumOutputBytes) else {
                return error(id, -32602, MCPBatchReceiptBudget.refusal, terminal: .receiptID)
            }
        }
        do {
            try HeadlessAutomationAuthority.validateDiagnosed(command: name, arguments: arguments)
        } catch HeadlessAutomationAuthorityError.unavailableCommand {
            return toolFailure(id, "Tool is unavailable through headless automation.")
        } catch let error as ToolArgumentError {
            if name == "decompile", case ScriptingError.invalidArgument(let detail) = error.legacyError,
               [#"format must be "text" or "lines""#, #"lineRange must be "a-b" with 1 <= a <= b"#,
                "lineRange cannot be combined with cursor", "malformed cursor"].contains(detail) {
                return toolFailure(id, "Tool call failed: Invalid argument: " + detail + ".")
            }
            return toolFailure(id, error.refusal.text)
        } catch {
            return self.error(id, -32602, "Invalid params",
                terminal: .invalidParams(field: nil, expected: nil))
        }
        let dispatchArguments = HeadlessAutomationAuthority.decompileMCPArguments(command: name, arguments: arguments)

        if let startup, startup.status.snapshot().state != "ready" {
            if name == "info", let milliseconds = arguments["waitForReadyMs"]?.intValue {
                await startup.waitUntilSettled(maximumMilliseconds: milliseconds)
            }
            if Task.isCancelled { return error(id, -32800, "Request cancelled") }
            if let reply = startupReply(id, name: name, protocolVersion: protocolVersion) { return reply }
        }
        if Task.isCancelled {
            return error(id, -32800, "Request cancelled")
        }
        let started = monotonicNow()
        do {
            try validateWorkspaceIdentity()
        } catch {
            return toolFailure(id, "Workspace identity validation failed.")
        }

        let output: ScriptValue?
        var dispatchNote: ScriptValue?
        let generationCapture = ScriptingGenerationCapture()
        var reportFailure: String?
        var reportedOutcome = "returned"
        var failureMessage = "Tool call failed."
        do {
            try Task.checkCancellation()
            if let asyncCommandExecutor {
                output = try await ScriptingGenerationCapture.$current.withValue(generationCapture) {
                    try await asyncCommandExecutor(name, dispatchArguments)
                }
            } else {
                guard let api else { return toolFailure(id, "Analysis is unavailable.") }
                let annotated = try await ScriptingGenerationCapture.$current.withValue(generationCapture) {
                    try await HeadlessAutomationAuthority.executeAsyncAnnotated(
                        command: name, arguments: dispatchArguments, api: api, proposingPrincipal: .mcp)
                }
                output = annotated.result
                dispatchNote = annotated.note
            }
        } catch ScriptingError.staleEvidence(let basedOn, let current) {
            return staleEvidenceFailure(id, basedOn: basedOn, current: current)
        } catch is CancellationError where name == "function-facts" {
            return self.error(id, -32800, "Request cancelled")
        } catch let failure as ScriptingWriteReadbackFailure {
            if failure.rolledBack { MCPExecutionFence.outcome?.rolledBack() }
            return writeReadbackFailure(id, failure)
        } catch let failure as ScriptingCommittedBatchFailure {
            output = failure.result ?? failure.receipt.fields
            MCPExecutionFence.outcome?.recordBatchReceipt(failure.receipt)
            MCPExecutionFence.outcome?.returned()
            reportFailure = failure.reason
        } catch let failure as ScriptingJournalFailure {
            output = failure.result
            if failure.handlerReturned { MCPExecutionFence.outcome?.returned() }
            reportFailure = failure.localizedDescription
            if !failure.liveApplied { reportedOutcome = "unknown" }
            else if !failure.handlerReturned { reportedOutcome = "applied-with-handler-error" }
        } catch let failure as MCPPostMutationReportFailure {
            output = failure.result
            MCPExecutionFence.outcome?.returned()
            reportFailure = (failure.underlying as? LocalizedError)?.errorDescription ?? "Mutation reporting failed."
        } catch {
            // Scripting errors are user-facing descriptions ("no function named 'x'"); surface them
            // so an agent can correct its call instead of retrying blind.
            output = nil
            if let refusal = MCPToolRefusal.executionRefusal(error) {
                failureMessage = refusal.text
            } else if let described = (error as? LocalizedError)?.errorDescription, !described.isEmpty {
                failureMessage = "Tool call failed: " + String(described.prefix(1_024))
            }
        }
        if output != nil, HeadlessAutomationAuthority.catalogSnapshot.command(named: name)?.mutates == true {
            MCPExecutionFence.outcome?.returned()
        }
        if MCPBatchReceiptBudget.commands.contains(name), let count = output?["count"]?.intValue,
           let changed = output?["changed"]?.intValue {
            MCPExecutionFence.outcome?.recordBatchReceipt(.init(command: name, count: count, changed: changed,
                imageSlot: MCPExecutionFence.outcome?.batchReceipt?.imageSlot ?? output?["imageSlot"]?.intValue))
        }
        do {
            try validateWorkspaceIdentity()
        } catch {
            if MCPBatchReceiptBudget.commands.contains(name), let receipt = MCPExecutionFence.outcome?.batchReceipt {
                let journal = reportFailure == nil ? "" : "; edit-journal-failed"
                return toolFailure(id, "\(receipt.summary); identity validation failed\(journal). Do not retry automatically.")
            }
            if (output != nil || (MCPExecutionFence.outcome?.snapshot ?? .notStarted) != .notStarted),
               HeadlessAutomationAuthority.catalogSnapshot.command(named: name)?.mutates == true {
                return self.error(id, -32603, "Mutation outcome requires inspection; identity validation failed. Do not retry automatically.")
            }
            return toolFailure(id, "Workspace identity validation failed.")
        }
        // A mutation that already committed is reported as committed: answering "cancelled" or
        // "deadline exceeded" for applied work invites a retry that applies it twice.
        let committedMutation = (output != nil || (MCPExecutionFence.outcome?.snapshot ?? .notStarted) != .notStarted)
            && HeadlessAutomationAuthority.catalogSnapshot.command(named: name)?.mutates != false
        if Task.isCancelled, !committedMutation {
            return error(id, -32800, "Request cancelled")
        }
        let finished = monotonicNow()
        let elapsed = finished >= started ? finished - started : UInt64.max
        guard elapsed <= configuration.maximumToolDurationNanoseconds || committedMutation else {
            return error(id, -32001, "Request deadline exceeded", terminal: .deadline(
                limitNanoseconds: configuration.maximumToolDurationNanoseconds,
                usedNanoseconds: elapsed))
        }

        guard var output = output.map({ withStartupAnalysis(name, $0) }) else {
            if let receipt = MCPExecutionFence.outcome?.batchReceipt {
                return toolFailure(id, receipt.summary + "; " + failureMessage + " Do not retry automatically.")
            }
            let caution = MCPExecutionFence.outcome?.snapshot == .unknown ? " Mutation outcome unknown; do not retry automatically." : ""
            return toolFailure(id, failureMessage + caution)
        }
        if let reportFailure {
            output = .object(["returnedResult": output, "reportingError": .string(reportFailure),
                              "mutationOutcome": .string(reportedOutcome), "retrySafe": .bool(false)])
        }
        let hasReportingFailure = reportFailure != nil || VerifiedAnnotationFailure.isFailedReply(output)
        // The async binding encodes off the MainActor: a large (bounded) result never blocks the
        // UI while it is serialized (DP09-2 N3).
        let limit = configuration.maximumOutputBytes / 2
        let encodedOutput = output
        let outputDepth = MCPStructuredResult.maximumOutputDepth(
            protocolVersion: protocolVersion, isError: hasReportingFailure, output: encodedOutput)
        let factsEncodingProbe = name == "function-facts" ? api?.snapshotReadCheckpoint : nil
        let encoded: OutputEncoding = await Task.detached(priority: Task.currentPriority) {
            MCPFatalSignalReporter.prepareAlternateStack()
            factsEncodingProbe?()
            let data: Data
            do { data = try encodedOutput.jsonData(maximumDepth: outputDepth) }
            catch let refusal as ScriptValueEncodingError { return .nonFinite(refusal) }
            catch { return .encoding }
            guard data.count <= limit else { return .limit(data.count) }
            factsEncodingProbe?()
            guard let string = String(data: data, encoding: .utf8) else { return .encoding }
            return .text(string)
        }.value
        let text: String
        switch encoded {
        case let .text(string): text = string
        case let .limit(used): return outputLimitFailure(id, used: used)
        case .encoding: return outputLimitFailure(id)
        case let .nonFinite(refusal): return outputLimitFailure(id, nonFinite: refusal)
        }
        var response = result(id, MCPStructuredResult.successEnvelope(
            protocolVersion: protocolVersion, tool: name, output: output,
            legacyText: text, isError: hasReportingFailure, generation: generationCapture))
        if let dispatchNote {
            let base = response
            let maximum = configuration.maximumOutputBytes
            response = await Task.detached(priority: Task.currentPriority) {
                MCPFatalSignalReporter.prepareAlternateStack()
                guard let noteData = try? ScriptValue.object(["note": dispatchNote]).jsonData(),
                      noteData.count <= limit else { return base }
                let noteText = String(decoding: noteData, as: UTF8.self)
                let candidate = ScriptValue.object([
                    "jsonrpc": .string("2.0"), "id": id ?? .null,
                    "result": MCPStructuredResult.successEnvelope(
                        protocolVersion: protocolVersion, tool: name, output: encodedOutput,
                        legacyText: text, isError: hasReportingFailure, generation: generationCapture,
                        note: dispatchNote, noteText: noteText),
                ])
                guard let data = try? candidate.jsonData(), data.count <= maximum else { return base }
                return candidate
            }.value
        }
        if name == "function-facts" {
            // Encoding is bounded but still asynchronous. A cancelled facts read
            // must not publish the success assembled before that suspension.
            if Task.isCancelled { return error(id, -32800, "Request cancelled") }
            do { try validateWorkspaceIdentity() }
            catch { return toolFailure(id, "Workspace identity validation failed.") }
        }
        return response
    }

    private func toolsCall(
        id: ScriptValue?, requestKey: RequestKey?, params: ScriptValue?
    ) -> ScriptValue {
        let protocolVersion = session.resultProtocol
        guard case .some(.object(let fields)) = params,
              Set(fields.keys).isSubset(of: ["name", "arguments", "_meta"]),
              let name = fields["name"]?.stringValue,
              !name.isEmpty,
              name.utf8.count <= 256,
              !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            return error(id, -32602, "Invalid params",
                terminal: .invalidParams(field: nil, expected: nil))
        }
        if let metadata = fields["_meta"], case .object = metadata {
            // Metadata is admitted only as an object and is deliberately not forwarded.
        } else if fields["_meta"] != nil {
            return error(id, -32602, "Invalid params",
                terminal: .invalidParams(field: "params._meta", expected: "object"))
        }
        let arguments: ScriptValue
        switch fields["arguments"] {
        case .none, .some(.null):
            arguments = .object([:])
        case .some(let value):
            guard case .object = value else {
                return error(id, -32602, "Invalid params",
                    terminal: .invalidParams(field: "params.arguments", expected: "object or null"))
            }
            arguments = value
        }
        if let allowedCommands, !allowedCommands.contains(name) {
            return toolFailure(id, "Tool is unavailable through headless automation.")
        }
        if MCPBatchReceiptBudget.commands.contains(name) {
            guard let encodedID = try? (id ?? .null).jsonData(),
                  MCPBatchReceiptBudget.admits(idBytes: encodedID.count, maximumBytes: configuration.maximumOutputBytes) else {
                return error(id, -32602, MCPBatchReceiptBudget.refusal, terminal: .receiptID)
            }
        }
        do {
            try HeadlessAutomationAuthority.validateDiagnosed(command: name, arguments: arguments)
        } catch HeadlessAutomationAuthorityError.unavailableCommand {
            return toolFailure(id, "Tool is unavailable through headless automation.")
        } catch let error as ToolArgumentError {
            if name == "decompile", case ScriptingError.invalidArgument(let detail) = error.legacyError,
               [#"format must be "text" or "lines""#, #"lineRange must be "a-b" with 1 <= a <= b"#,
                "lineRange cannot be combined with cursor", "malformed cursor"].contains(detail) {
                return toolFailure(id, "Tool call failed: Invalid argument: " + detail + ".")
            }
            return toolFailure(id, error.refusal.text)
        } catch {
            return self.error(id, -32602, "Invalid params",
                terminal: .invalidParams(field: nil, expected: nil))
        }
        let dispatchArguments = HeadlessAutomationAuthority.decompileMCPArguments(command: name, arguments: arguments)

        if let reply = startupReply(id, name: name, protocolVersion: protocolVersion) { return reply }
        if let requestKey, session.consumeCancellation(requestKey) {
            return error(id, -32800, "Request cancelled")
        }
        let started = monotonicNow()
        do {
            try validateWorkspaceIdentity()
        } catch {
            return toolFailure(id, "Workspace identity validation failed.")
        }

        let output: ScriptValue?
        var reportFailure: String?
        var reportedOutcome = "returned"
        let generationCapture = ScriptingGenerationCapture()
        var failureMessage = "Tool call failed."
        do {
            guard let api else { return toolFailure(id, "Analysis is unavailable.") }
            output = try ScriptingGenerationCapture.$current.withValue(generationCapture) {
                try HeadlessAutomationAuthority.execute(
                    command: name, arguments: dispatchArguments, api: api, proposingPrincipal: .mcp)
            }
        } catch ScriptingError.staleEvidence(let basedOn, let current) {
            return staleEvidenceFailure(id, basedOn: basedOn, current: current)
        } catch is CancellationError where name == "function-facts" {
            return self.error(id, -32800, "Request cancelled")
        } catch let failure as ScriptingWriteReadbackFailure {
            if failure.rolledBack { MCPExecutionFence.outcome?.rolledBack() }
            return writeReadbackFailure(id, failure)
        } catch let failure as ScriptingCommittedBatchFailure {
            output = failure.result ?? failure.receipt.fields
            MCPExecutionFence.outcome?.recordBatchReceipt(failure.receipt)
            MCPExecutionFence.outcome?.returned()
            reportFailure = failure.reason
        } catch let failure as ScriptingJournalFailure {
            output = failure.result
            if failure.handlerReturned { MCPExecutionFence.outcome?.returned() }
            reportFailure = failure.localizedDescription
            if !failure.liveApplied { reportedOutcome = "unknown" }
            else if !failure.handlerReturned { reportedOutcome = "applied-with-handler-error" }
        } catch let failure as MCPPostMutationReportFailure {
            output = failure.result
            MCPExecutionFence.outcome?.returned()
            reportFailure = (failure.underlying as? LocalizedError)?.errorDescription ?? "Mutation reporting failed."
        } catch {
            // Scripting errors are user-facing descriptions ("no function named 'x'"); surface them
            // so an agent can correct its call instead of retrying blind.
            output = nil
            if let refusal = MCPToolRefusal.executionRefusal(error) {
                failureMessage = refusal.text
            } else if let described = (error as? LocalizedError)?.errorDescription, !described.isEmpty {
                failureMessage = "Tool call failed: " + String(described.prefix(1_024))
            }
        }
        if output != nil, HeadlessAutomationAuthority.catalogSnapshot.command(named: name)?.mutates == true {
            MCPExecutionFence.outcome?.returned()
        }
        if MCPBatchReceiptBudget.commands.contains(name), let count = output?["count"]?.intValue,
           let changed = output?["changed"]?.intValue {
            MCPExecutionFence.outcome?.recordBatchReceipt(.init(command: name, count: count, changed: changed,
                imageSlot: MCPExecutionFence.outcome?.batchReceipt?.imageSlot ?? output?["imageSlot"]?.intValue))
        }
        do {
            try validateWorkspaceIdentity()
        } catch {
            if MCPBatchReceiptBudget.commands.contains(name), let receipt = MCPExecutionFence.outcome?.batchReceipt {
                let journal = reportFailure == nil ? "" : "; edit-journal-failed"
                return toolFailure(id, "\(receipt.summary); identity validation failed\(journal). Do not retry automatically.")
            }
            if (output != nil || (MCPExecutionFence.outcome?.snapshot ?? .notStarted) != .notStarted),
               HeadlessAutomationAuthority.catalogSnapshot.command(named: name)?.mutates == true {
                return self.error(id, -32603, "Mutation outcome requires inspection; identity validation failed. Do not retry automatically.")
            }
            return toolFailure(id, "Workspace identity validation failed.")
        }
        // A mutation that already committed is reported as committed: answering "cancelled" or
        // "deadline exceeded" for applied work invites a retry that applies it twice.
        let committedMutation = (output != nil || (MCPExecutionFence.outcome?.snapshot ?? .notStarted) != .notStarted)
            && HeadlessAutomationAuthority.catalogSnapshot.command(named: name)?.mutates != false
        if let requestKey, session.consumeCancellation(requestKey), !committedMutation {
            return error(id, -32800, "Request cancelled")
        }
        if name == "function-facts", Task.isCancelled {
            return error(id, -32800, "Request cancelled")
        }
        let finished = monotonicNow()
        let elapsed = finished >= started ? finished - started : UInt64.max
        guard elapsed <= configuration.maximumToolDurationNanoseconds || committedMutation else {
            return error(id, -32001, "Request deadline exceeded", terminal: .deadline(
                limitNanoseconds: configuration.maximumToolDurationNanoseconds,
                usedNanoseconds: elapsed))
        }

        guard var output = output.map({ withStartupAnalysis(name, $0) }) else {
            if let receipt = MCPExecutionFence.outcome?.batchReceipt {
                return toolFailure(id, receipt.summary + "; " + failureMessage + " Do not retry automatically.")
            }
            let caution = MCPExecutionFence.outcome?.snapshot == .unknown ? " Mutation outcome unknown; do not retry automatically." : ""
            return toolFailure(id, failureMessage + caution)
        }
        if let reportFailure {
            output = .object(["returnedResult": output, "reportingError": .string(reportFailure),
                              "mutationOutcome": .string(reportedOutcome), "retrySafe": .bool(false)])
        }
        let hasReportingFailure = reportFailure != nil || VerifiedAnnotationFailure.isFailedReply(output)
        let outputDepth = MCPStructuredResult.maximumOutputDepth(
            protocolVersion: protocolVersion, isError: hasReportingFailure, output: output)
        let factsEncodingProbe = name == "function-facts" ? api?.snapshotReadCheckpoint : nil
        factsEncodingProbe?()
        let outputData: Data
        do { outputData = try output.jsonData(maximumDepth: outputDepth) }
        catch let refusal as ScriptValueEncodingError { return outputLimitFailure(id, nonFinite: refusal) }
        catch { return outputLimitFailure(id) }
        guard outputData.count <= configuration.maximumOutputBytes / 2 else {
            return outputLimitFailure(id, used: outputData.count)
        }
        guard let text = String(data: outputData, encoding: .utf8) else {
            return outputLimitFailure(id)
        }
        factsEncodingProbe?()
        if name == "function-facts", Task.isCancelled {
            return error(id, -32800, "Request cancelled")
        }
        return result(id, MCPStructuredResult.successEnvelope(
            protocolVersion: protocolVersion, tool: name, output: output,
            legacyText: text, isError: hasReportingFailure,
            generation: generationCapture))
    }

    private enum OutputEncoding: Sendable {
        case text(String)
        case limit(Int)
        case encoding
        case nonFinite(ScriptValueEncodingError)
    }

    /// A non-finite number in tool output is a malformed result, not an oversize one. The
    /// message names the path only; the offending value is never rendered.
    private func outputLimitFailure(_ id: ScriptValue?, nonFinite: ScriptValueEncodingError) -> ScriptValue {
        guard case let .nonFiniteNumber(path, truncated) = nonFinite else { return outputLimitFailure(id) }
        let detail = "tool output contained a non-finite number at \(String(reflecting: path))"
            + (truncated ? " (path truncated)" : "")
        guard let receipt = MCPExecutionFence.outcome?.batchReceipt else {
            return error(id, -32603, "Tool output contained a non-finite number at \(String(reflecting: path))"
                + (truncated ? " (path truncated)" : ""), terminal: .encoding)
        }
        return toolFailure(id, receipt.summary + "; " + detail + ". Do not retry automatically.")
    }

    private func outputLimitFailure(_ id: ScriptValue?, used: Int? = nil) -> ScriptValue {
        guard let receipt = MCPExecutionFence.outcome?.batchReceipt else {
            let terminal = used.map {
                MCPServerTerminal.output(limit: configuration.maximumOutputBytes / 2, used: $0)
            } ?? .encoding
            return error(id, -32603, "Response exceeds limit", terminal: terminal)
        }
        let terminal = used.map {
            MCPServerTerminal.output(limit: configuration.maximumOutputBytes / 2, used: $0)
        } ?? .encoding
        return result(id, .object([
            "content": .array([
                .object(["type": .string("text"), "text": .string(receipt.summary + "; response exceeds limit. Do not retry automatically.")]),
                .object(["type": .string("text"), "text": .string(terminal.refusal.text)]),
            ]),
            "isError": .bool(true),
        ]))
    }

    private func toolFailure(_ id: ScriptValue?, _ message: String) -> ScriptValue {
        result(id, .object([
            "content": .array([.object(["type": .string("text"), "text": .string(message)])]),
            "isError": .bool(true),
        ]))
    }

    private func writeReadbackFailure(_ id: ScriptValue?, _ failure: ScriptingWriteReadbackFailure) -> ScriptValue {
        guard let data = try? failure.reply.jsonData(), let text = String(data: data, encoding: .utf8) else {
            return toolFailure(id, failure.localizedDescription)
        }
        // Same typed-content envelope as staleEvidence. No returnedResult,
        // committed batch receipt, or successful-write isError=false envelope.
        return result(id, .object([
            "content": .array([.object(["type": .string("text"), "text": .string(text)])]),
            "isError": .bool(true),
        ]))
    }

    /// A typed tool error, never an applied-mutation receipt and never staleCursor.
    private func staleEvidenceFailure(_ id: ScriptValue?, basedOn: UUID, current: UUID) -> ScriptValue {
        let refusal = WorkspaceScriptingAPI.staleEvidenceReply(basedOn: basedOn, current: current)
        guard let data = try? refusal.jsonData(), let text = String(data: data, encoding: .utf8) else {
            return toolFailure(id, "staleEvidence")
        }
        return result(id, .object([
            "content": .array([.object(["type": .string("text"), "text": .string(text)])]),
            "isError": .bool(true),
            "_meta": .object(["generation": .string(current.uuidString)]),
        ]))
    }

    private func recordCancellation(_ params: ScriptValue?) {
        guard case .some(.object(let fields)) = params,
              Set(fields.keys).isSubset(of: ["requestId", "reason"]),
              let key = requestKey(fields["requestId"]) else { return }
        session.recordCancellation(key)
    }

    // MARK: - Envelopes and encoding

    private func result(_ id: ScriptValue?, _ value: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": id ?? .null, "result": value])
    }

    private func error(_ id: ScriptValue?, _ code: Int, _ message: String,
                       terminal: MCPServerTerminal? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "code": .int(Int64(code)), "message": .string(message)
        ]
        if let terminal { fields["data"] = terminal.scriptValue }
        return .object([
            "jsonrpc": .string("2.0"), "id": id ?? .null, "error": .object(fields)
        ])
    }

    func encodeBounded(_ response: ScriptValue, restoringID: Phase2ProductionJSONValue? = nil) -> Data? {
        let fence = MCPExecutionFence.connection ?? session.fence
        guard !fence.isFailed else { return nil }
        do {
            let idBytes = try (response["id"] ?? .null).jsonData()
            let id = try restoringID ?? Phase2StrictJSONParser().parse(idBytes, limits: .providerEnvelope)
            let data: Data?
            do { data = try response.jsonData() }
            catch is ScriptValueEncodingError { data = nil }
            catch is ScriptValueNestingError { data = nil }
            var fallback: String, compact: String
            switch MCPExecutionFence.outcome?.snapshot ?? .notStarted {
            case .notStarted: fallback = "Response exceeds limit"; compact = ""
            case .unknown: fallback = "Mutation outcome unknown; do not retry automatically."; compact = "Outcome unknown; no retry"
            case .returned: fallback = "Operation returned; do not retry automatically."; compact = "Returned; no retry"
            case .committed: fallback = "Mutation committed; do not retry."; compact = "Committed; no retry"
            case .rolledBack: fallback = "Write rolled back; read fresh state before retrying."; compact = "Rolled back"
            }
            if let receipt = MCPExecutionFence.outcome?.batchReceipt {
                fallback = receipt.summary + "; reporting failed. Do not retry automatically."
                compact = fallback
            }
            if let data {
                return try MCPFrameAdmission.response(data, id: id, maximumBytes: configuration.maximumOutputBytes,
                    failureMessage: fallback, compactMessage: compact,
                    receiptResultText: MCPExecutionFence.outcome?.batchReceipt.map {
                        $0.summary + "; response exceeds limit. Do not retry automatically."
                    })
            }
            let recovery = MCPServerTerminal.encoding.frame(id: id, code: -32603, message: fallback)
            return try MCPFrameAdmission.response(recovery, id: id,
                maximumBytes: configuration.maximumOutputBytes,
                failureMessage: fallback, compactMessage: compact)
        } catch {
            fence.fail()
            return nil
        }
    }

    private func validObjectParams(_ params: ScriptValue?) -> Bool {
        guard let params else { return true }
        if case .object = params { return true }
        return false
    }

    private func validResponseID(_ id: ScriptValue?, isPresent: Bool) -> Bool {
        guard isPresent else { return true }
        switch id {
        case .some(.null), .some(.int):
            return true
        case .some(.double(let value)):
            return value.isFinite
        case .some(.string(let value)):
            return value.utf8.count <= 256
                && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        default:
            return false
        }
    }

    private func requestKey(_ id: ScriptValue?) -> RequestKey? {
        switch id {
        case .some(.int(let value)): return .integer(value)
        case .some(.double(let value)) where value.isFinite: return .number(value)
        case .some(.string(let value)) where value.utf8.count <= 256: return .string(value)
        default: return nil
        }
    }

    private static func isJSONWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private enum RequestKey: Hashable {
        case integer(Int64)
        case number(Double)
        case string(String)
    }

    private final class SessionState {
        let fence = MCPConnectionFence()
        private let protocolLock = NSLock()
        private var negotiatedProtocol: MCPResultProtocol = .legacy

        var resultProtocol: MCPResultProtocol {
            protocolLock.lock(); defer { protocolLock.unlock() }
            return negotiatedProtocol
        }

        /// A second initialize changes future admissions, never the captured value of a call.
        func negotiate(_ offered: ScriptValue?) -> MCPResultProtocol {
            let version = MCPResultProtocol.negotiate(offered)
            protocolLock.lock(); defer { protocolLock.unlock() }
            negotiatedProtocol = version
            return version
        }

        private let maximumCancellations: Int
        private var cancelled: Set<RequestKey> = []
        private var cancellationOrder: [RequestKey] = []

        init(maximumCancellations: Int) {
            self.maximumCancellations = maximumCancellations
        }

        func recordCancellation(_ key: RequestKey) {
            guard cancelled.insert(key).inserted else { return }
            cancellationOrder.append(key)
            if cancellationOrder.count > maximumCancellations {
                cancelled.remove(cancellationOrder.removeFirst())
            }
        }

        func consumeCancellation(_ key: RequestKey) -> Bool {
            guard cancelled.remove(key) != nil else { return false }
            cancellationOrder.removeAll { $0 == key }
            return true
        }
    }

    private final class BoundedLineReader: @unchecked Sendable {
        enum Event: Sendable {
            case message(Data)
            case oversized
            case end
        }

        private let descriptor: Int32
        private let maximumLineBytes: Int
        private var storage = Data()
        private var discardingOversizedLine = false
        private var reachedEOF = false
        private let stopLock = NSLock()
        private var stopped = false

        func stop() { stopLock.withLock { stopped = true } }
        private var isStopped: Bool { stopLock.withLock { stopped } }

        init(descriptor: Int32, maximumLineBytes: Int) {
            self.descriptor = descriptor
            self.maximumLineBytes = maximumLineBytes
        }

        func next() throws -> Event {
            while true {
                if isStopped { return .end }
                if discardingOversizedLine {
                    if let newline = storage.firstIndex(of: 0x0A) {
                        storage.removeSubrange(storage.startIndex...newline)
                        discardingOversizedLine = false
                        return .oversized
                    }
                    storage.removeAll(keepingCapacity: true)
                    if reachedEOF {
                        discardingOversizedLine = false
                        return .oversized
                    }
                    try readChunk()
                    continue
                }

                if let newline = storage.firstIndex(of: 0x0A) {
                    let line = Data(storage[..<newline])
                    storage.removeSubrange(storage.startIndex...newline)
                    return line.count <= maximumLineBytes ? .message(line) : .oversized
                }
                if storage.count > maximumLineBytes {
                    discardingOversizedLine = true
                    continue
                }
                if reachedEOF {
                    guard !storage.isEmpty else { return .end }
                    let line = storage
                    storage.removeAll()
                    return line.count <= maximumLineBytes ? .message(line) : .oversized
                }
                try readChunk()
            }
        }

        private func readChunk() throws {
            var bytes = [UInt8](repeating: 0, count: 16 * 1_024)
            while true {
                if isStopped { reachedEOF = true; return }
                // Poll, rather than close a descriptor underneath a read, so a
                // failed output unblocks an idle client without FD-reuse races.
                var descriptorState = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                let ready = Darwin.poll(&descriptorState, 1, 25)
                if ready < 0, errno == EINTR { continue }
                guard ready >= 0 else { throw HeadlessProtocolIOError.descriptorFailure }
                if ready == 0 { continue }
                let count = bytes.withUnsafeMutableBytes { buffer in
                    Darwin.read(descriptor, buffer.baseAddress, buffer.count)
                }
                if count < 0, errno == EINTR { continue }
                guard count >= 0 else { throw HeadlessProtocolIOError.descriptorFailure }
                if count == 0 {
                    reachedEOF = true
                } else {
                    storage.append(contentsOf: bytes.prefix(count))
                }
                return
            }
        }
    }
}
