import Foundation

/// Everything a metadata-only retained-input load needs, captured on the MainActor from values the
/// store already holds. Nothing here is re-hashed or re-verified; identity and integrity are reused.
struct AIRSCapturedInput: Sendable {
    let imageID: UUID
    let bytes: Data
    let sourceURL: URL
    let identity: MachOSliceArtifactIdentity
    let layout: MachOPreferredSegmentLayout
    let integrity: MachOSliceArtifactIntegrityState
}

/// Why a bounded wait ended without a value.
enum AIRSWaitFailure: Error, Equatable, Sendable { case deadline, cancelled }

private final class AIRSAwaitOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<T, AIRSWaitFailure>, Never>?
    private var finished = false
    private var pending: Result<T, AIRSWaitFailure>?
    private var timer: Task<Void, Never>?
    /// Stored under the lock; a timer registered after completion is cancelled at once.
    func setTimer(_ task: Task<Void, Never>) {
        lock.lock()
        if finished { lock.unlock(); task.cancel(); return }
        timer = task
        lock.unlock()
    }
    func install(_ value: CheckedContinuation<Result<T, AIRSWaitFailure>, Never>) {
        lock.lock()
        if let pending { lock.unlock(); value.resume(returning: pending); return }
        continuation = value
        lock.unlock()
    }
    func finish(_ result: Result<T, AIRSWaitFailure>) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let waiting = continuation
        continuation = nil
        if waiting == nil { pending = result }
        let pendingTimer = timer
        timer = nil
        lock.unlock()
        pendingTimer?.cancel()
        waiting?.resume(returning: result)
    }
}

/// Race a unit of asynchronous work against a logical deadline and the caller's cancellation. The
/// deadline is logical only: synchronous loader or analyzer work is not interrupted, so the work keeps
/// its worker slot until it really returns.
func airsAwait<T: Sendable>(deadlineMillis: Int, _ work: @escaping @Sendable () async -> T) async -> Result<T, AIRSWaitFailure> {
    let once = AIRSAwaitOnce<T>()
    return await withTaskCancellationHandler {
        await withCheckedContinuation { (continuation: CheckedContinuation<Result<T, AIRSWaitFailure>, Never>) in
            once.install(continuation)
            once.setTimer(Task {
                try? await Task.sleep(nanoseconds: UInt64(max(deadlineMillis, 0)) * 1_000_000)
                once.finish(.failure(.deadline))
            })
            Task { once.finish(.success(await work())) }
        }
    } onCancel: {
        once.finish(.failure(.cancelled))
    }
}

/// Serial census worker: at most one metadata-only parse runs at a time per process.
actor AIRSReadCaptureWorker {
    static let shared = AIRSReadCaptureWorker()

    func census(_ input: AIRSCapturedInput, loader: @Sendable (AIRSCapturedInput) throws -> AIRSCensus) -> Result<AIRSCensus, AIRSCaptureFailure> {
        do { return .success(try loader(input)) }
        catch { return .failure(.init(describing: error)) }
    }
}

struct AIRSCaptureFailure: Error, Equatable, Sendable {
    let code: String
    init(describing error: Error) {
        if let retained = error as? MachOBinaryLoader.RetainedInputError {
            code = "\(retained)"
        } else {
            code = "loader_error"
        }
    }
    init(code: String) { self.code = code }
}

enum AIRSReadInputCapture {
    /// New read-admission cap: retained bytes captured for one parse.
    static let maximumRetainedBytes = 128 * 1_024 * 1_024

    static func withinBound(_ input: AIRSCapturedInput) -> Bool { input.bytes.count <= maximumRetainedBytes }

    /// The existing metadata-only load, projected to raw and unique starts. No analysis is rerun.
    static func liveCensus(_ input: AIRSCapturedInput) throws -> AIRSCensus {
        let binary = try MachOBinaryLoader().load(retainedBytes: input.bytes, sourceURL: input.sourceURL,
            verifiedIdentity: input.identity, layout: input.layout, integrity: input.integrity)
        return AIRSCensus(binary: binary)
    }
}
