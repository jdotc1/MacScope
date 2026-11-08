import Foundation

enum DecompileBudgetRefusal: LocalizedError, Equatable {
    case tooLarge(bytes: UInt64, blocks: Int)
    case deadline(milliseconds: UInt64)

    var errorDescription: String? {
        switch self {
        case .tooLarge(let bytes, let blocks):
            return "function too large: \(bytes) bytes, \(blocks) blocks (limits: 262144 bytes, 8192 blocks); refused before lifting"
        case .deadline(let milliseconds):
            return "decompile deadline: no result within \(milliseconds) ms; the read was cancelled and no partial output is returned"
        }
    }
}

extension WorkspaceScriptingAPI {
    nonisolated static let maximumDecompileFunctionBytes: UInt64 = 262_144
    nonisolated static let maximumDecompileFunctionBlocks = 8_192
    nonisolated static let defaultDecompileDeadlineNanoseconds: UInt64 = 27_000_000_000
    /// E2 caps on the authored comments rendered into ONE decompile: the single site for both numbers.
    /// Going over either is an atomic typed `budgetExceeded` refusal, never a truncated comment set.
    nonisolated static let maximumUserCommentsPerDecompile = 4_096
    nonisolated static let maximumUserCommentBytesPerDecompile = 1_048_576

    nonisolated static func decompileSizeCheck(
        _ function: FunctionSummary, in slot: ImageSlot, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws {
        let hasExtent = function.endAddress > function.startAddress
        let bytes = hasExtent ? function.endAddress - function.startAddress : 0
        var blocks = 0
        let trace = NativeDecompilerPhaseRecord.current()
        var visited = 0
        defer { trace?.add(.blocksVisited, UInt64(visited)) }
        for (index, block) in (snapshot.analysis(in: slot)?.basicBlocks ?? []).enumerated() {
            if index > 0, index.isMultiple(of: 1_024) { try checkpoint() }
            visited += 1
            // Equivalent to functionRange for representable ranges, without start+1 overflow.
            let contains = hasExtent
                ? block.startAddress >= function.startAddress && block.startAddress < function.endAddress
                : block.startAddress == function.startAddress
            if contains { blocks += 1 }
        }
        try checkpoint()
        guard bytes <= maximumDecompileFunctionBytes, blocks <= maximumDecompileFunctionBlocks else {
            throw DecompileBudgetRefusal.tooLarge(bytes: bytes, blocks: blocks)
        }
    }

    nonisolated static func awaitSnapshotRead(
        _ work: Task<ScriptValue, any Error>,
        deadlineNanoseconds: UInt64?,
        onExpiry: @escaping @Sendable () -> Void
    ) async throws -> ScriptValue {
        guard let deadline = deadlineNanoseconds else { return try await work.value }
        let race = DecompileReadRace()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard race.install(continuation) else { return }
                let timer = Task.detached(priority: Task.currentPriority) {
                    do { try await Task.sleep(nanoseconds: deadline) } catch { return }
                    // The observer may still be awaiting a non-checkpointed rendering span.
                    guard !Task.isCancelled else { return }
                    if work.isCancelled {
                        _ = race.finish(.failure(CancellationError()))
                    } else if race.finish(.failure(DecompileBudgetRefusal.deadline(
                        milliseconds: deadline / 1_000_000))) {
                        // Resume first; cancellation is cooperative and must not delay the reply.
                        onExpiry()
                    }
                }
                race.installTimer(timer)
                Task.detached(priority: Task.currentPriority) {
                    let result = await work.result
                    _ = race.finish(result)
                }
            }
        } onCancel: {
            // The enclosing handler cancels the work and its plain-thread token.
            // This handler releases the waiter even if that work cannot yet checkpoint.
            _ = race.finish(.failure(CancellationError()))
        }
    }
}

/// No await or continuation callback runs while the lock is held.
private final class DecompileReadRace: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ScriptValue, any Error>?
    private var outcome: Result<ScriptValue, any Error>?
    private var timer: Task<Void, Never>?

    func install(_ value: CheckedContinuation<ScriptValue, any Error>) -> Bool {
        lock.lock()
        if let outcome {
            lock.unlock()
            value.resume(with: outcome)
            return false
        }
        continuation = value
        lock.unlock()
        return true
    }

    func installTimer(_ value: Task<Void, Never>) {
        lock.lock()
        let finished = outcome != nil
        if !finished { timer = value }
        lock.unlock()
        if finished { value.cancel() }
    }

    @discardableResult
    func finish(_ result: Result<ScriptValue, any Error>) -> Bool {
        lock.lock()
        guard outcome == nil else { lock.unlock(); return false }
        outcome = result
        let waiting = continuation
        continuation = nil
        let sleeping = timer
        timer = nil
        lock.unlock()
        waiting?.resume(with: result)
        sleeping?.cancel()
        return true
    }
}
