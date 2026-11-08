import Foundation

/// Inputs captured by optional work, not a WorkspaceSnapshot or full ImageAnalysis.
struct CallOwnerPreparationInput: Sendable {
    let memo: CallOwnerAdjacencyMemo
    let graphNames: GraphNameMemo
    let functions: [FunctionSummary]
    let symbols: [SymbolSummary]
    let xrefs: [XRef]

    init(_ analysis: ImageAnalysis) {
        memo = analysis.callOwnerAdjacencyMemo
        graphNames = analysis.graphNames
        functions = analysis.functions
        symbols = analysis.symbols
        xrefs = analysis.xrefs
    }
}

struct CallOwnerPrepared: Sendable {
    let id: UUID
    let names: GraphNameIndex
    let adjacency: CallOwnerAdjacencyIndex
}

/// ImageAnalysis replaces this memo on functions, symbols, or xrefs mutation.
/// Only background preparation and explicit synthetic tests call prepare.
final class CallOwnerAdjacencyMemo: @unchecked Sendable {
    private let lock = NSLock()
    private var cached: CallOwnerPrepared?
    private var building = false
    private var revision = UUID()

    enum PeekResult {
        case contended
        case value(CallOwnerPrepared?)
    }

    /// One non-blocking attempt. Contention is reported separately from a cold memo so a
    /// retained indexed cursor can retry instead of being refused as stale.
    func peekResult() -> PeekResult {
        guard lock.try() else { return .contended }
        defer { lock.unlock() }
        return .value(cached)
    }

    /// The first-page read path performs one non-blocking attempt; contention means cold.
    func peek() -> CallOwnerPrepared? {
        if case .value(let prepared) = peekResult() { return prepared }
        return nil
    }

    /// Bounded retry for a retained indexed cursor. The lock is only ever held for short
    /// field reads and writes (never across a build), so real contention clears in
    /// microseconds. Returns .contended only after the whole retry budget is spent.
    func peekRetryingContention(attempts: Int = 200,
                                pause: useconds_t = 1_000) -> PeekResult {
        var result = peekResult()
        var remaining = attempts
        while case .contended = result, remaining > 0 {
            usleep(pause)
            remaining -= 1
            result = peekResult()
        }
        return result
    }

    func prepare(analysis: ImageAnalysis,
                 checkpoint: () throws -> Void) throws -> CallOwnerPrepared? {
        try prepare(input: CallOwnerPreparationInput(analysis), checkpoint: checkpoint)
    }

    func prepare(input: CallOwnerPreparationInput,
                 checkpoint: () throws -> Void) throws -> CallOwnerPrepared? {
        try checkpoint()
        guard input.memo === self,
              input.xrefs.count >= CallOwnerAdjacencyIndex.minimumIndexedXRefs,
              input.xrefs.count <= CallOwnerAdjacencyIndex.maximumIndexedXRefs else { return nil }
        lock.lock()
        if let cached { lock.unlock(); return cached }
        guard !building else { lock.unlock(); return nil }
        building = true
        let ticket = revision
        lock.unlock()
        defer {
            lock.lock(); building = false; lock.unlock()
        }

        // Production callers are detached scheduler jobs. Direct tests with small
        // name tables may call on MainActor; GraphNameMemo keeps its own policy.
        let names = try input.graphNames.index(functions: input.functions,
            symbols: input.symbols, checkpoint: checkpoint)
        try checkpoint()
        guard let adjacency = try CallOwnerAdjacencyIndex.build(
            xrefs: input.xrefs, names: names, checkpoint: checkpoint) else { return nil }
        try checkpoint()
        let result = CallOwnerPrepared(id: UUID(), names: names, adjacency: adjacency)
        lock.lock()
        defer { lock.unlock() }
        guard revision == ticket else { return nil }
        cached = result
        return result
    }

    #if DEBUG
    /// Exercises loss/replacement of prepared data without changing snapshot generation.
    /// A build already in flight cannot publish after this revision change.
    /// DEBUG only: not compiled into Release.
    func discardPreparedForTesting() {
        lock.lock(); defer { lock.unlock() }
        cached = nil
        revision = UUID()
    }

    /// DEBUG only: not compiled into Release.
    func withLockHeldForTesting<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }
    #endif
}

enum CallReadBackend: Equatable, Sendable {
    case linear
    case indexed(UUID)
}

/// A pure decision over a single peek, never a builder or a lock acquisition.
func callReadBackend(rawCount: Int, prepared: CallOwnerPrepared?) -> CallReadBackend {
    guard rawCount >= CallOwnerAdjacencyIndex.minimumIndexedXRefs,
          rawCount <= CallOwnerAdjacencyIndex.maximumIndexedXRefs,
          let prepared, prepared.adjacency.count == rawCount else { return .linear }
    return .indexed(prepared.id)
}
