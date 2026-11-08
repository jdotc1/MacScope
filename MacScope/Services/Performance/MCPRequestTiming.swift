import Foundation
import OSLog

// Item 1282. Authored, unrun. Never transports, prints or persists a record.
enum MCPRequestStage: String, CaseIterable, Sendable {
    case admit, decode, catalog, dispatch, execute, encode, write, catalogBuild

    var signpostName: StaticString {
        switch self {
        case .admit: return "MCPAdmit"
        case .decode: return "MCPDecode"
        case .catalog: return "MCPCatalog"
        case .dispatch: return "MCPDispatch"
        case .execute: return "MCPExecute"
        case .encode: return "MCPEncode"
        case .write: return "MCPWrite"
        case .catalogBuild: return "MCPCatalogBuild"
        }
    }
}

struct MCPRequestTimingRecord: Sendable, Equatable {
    let stage: MCPRequestStage
    let start: Duration
    let end: Duration
    let requestOrdinal: UInt64
}

protocol MCPRequestTimingObserver: Sendable {
    // Synchronous, nonthrowing, called after the interval ends and without a lock.
    // Slow observers add caller-visible latency; observers must not block or reenter.
    func record(_ record: MCPRequestTimingRecord)
}

struct MCPRequestTiming: Sendable {
    private final class State: @unchecked Sendable {
        let observer: any MCPRequestTimingObserver
        let origin: ContinuousClock.Instant
        private let lock = NSLock()
        private var ordinal: UInt64 = 0

        init(observer: any MCPRequestTimingObserver) {
            self.observer = observer
            origin = ContinuousClock.now
        }

        func nextOrdinal() -> UInt64 {
            lock.lock()
            defer { lock.unlock() }
            // Diagnostic selection is finite; never silently wrap request identity.
            precondition(ordinal < UInt64.max, "MCP timing ordinal exhausted")
            ordinal += 1
            return ordinal
        }
    }

    private let state: State?
    private let ordinal: UInt64?
    static let disabled = Self(state: nil, ordinal: nil)
    // Only explicit withRequest installs context; a disabled call installs nothing.
    @TaskLocal static var current: Self = .disabled
    static let environmentKey = "MACSCOPE_MCP_REQUEST_TIMING"

    private init(state: State?, ordinal: UInt64?) {
        self.state = state
        self.ordinal = ordinal
    }

    init(observer: any MCPRequestTimingObserver) {
        state = State(observer: observer)
        ordinal = nil
    }

    // The caller passes its environment once; exact value "1" is the only opt-in.
    // In particular, neither process environment nor the observer is read per request.
    static func selected(
        environment: [String: String],
        observer: @autoclosure () -> any MCPRequestTimingObserver
    ) -> Self {
        guard environment[environmentKey] == "1" else { return .disabled }
        return Self(observer: observer())
    }

    // One ordinal per explicit boundary, shared by all nested stage measurements.
    // A standalone measure outside a boundary is its own diagnostic request.
    func withRequest<T>(_ body: () throws -> T) rethrows -> T {
        guard let state else { return try body() }
        let request = Self(state: state, ordinal: state.nextOrdinal())
        return try Self.$current.withValue(request, operation: body)
    }

    func withRequest<T>(
        isolation: isolated (any Actor)? = #isolation,
        _ body: () async throws -> T
    ) async rethrows -> T {
        guard let state else { return try await body() }
        let request = Self(state: state, ordinal: state.nextOrdinal())
        return try await Self.$current.withValue(request, operation: body)
    }

    func measure<T>(_ stage: MCPRequestStage, _ body: () throws -> T) rethrows -> T {
        guard let state else { return try body() }
        let requestOrdinal = ordinal ?? state.nextOrdinal()
        let start = state.origin.duration(to: ContinuousClock.now)
        let interval = MacScopePerformance.begin(stage.signpostName)
        defer {
            let end = state.origin.duration(to: ContinuousClock.now)
            MacScopePerformance.end(stage.signpostName, interval)
            state.observer.record(.init(stage: stage, start: start, end: end,
                                        requestOrdinal: requestOrdinal))
        }
        return try body()
    }

    func measure<T>(
        _ stage: MCPRequestStage,
        isolation: isolated (any Actor)? = #isolation,
        _ body: () async throws -> T
    ) async rethrows -> T {
        guard let state else { return try await body() }
        let requestOrdinal = ordinal ?? state.nextOrdinal()
        let start = state.origin.duration(to: ContinuousClock.now)
        let interval = MacScopePerformance.begin(stage.signpostName)
        defer {
            let end = state.origin.duration(to: ContinuousClock.now)
            MacScopePerformance.end(stage.signpostName, interval)
            state.observer.record(.init(stage: stage, start: start, end: end,
                                        requestOrdinal: requestOrdinal))
        }
        return try await body()
    }
}

// Every mutable property is protected by this lock; callbacks run outside State's lock.
// An opt-in, finite-session sink, not a production history or a bounded ring buffer.
final class MCPRequestTimingRecorder: MCPRequestTimingObserver, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [MCPRequestTimingRecord] = []

    func record(_ record: MCPRequestTimingRecord) {
        lock.lock()
        storage.append(record)
        lock.unlock()
    }

    var records: [MCPRequestTimingRecord] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}
