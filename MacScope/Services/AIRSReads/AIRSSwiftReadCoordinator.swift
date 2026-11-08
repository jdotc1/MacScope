import Foundation

/// What one whole-image Swift analysis produced. Retained immutable; filtering happens afterward.
struct AIRSSwiftRawResult: Sendable {
    enum Outcome: Sendable {
        case edges(SwiftErrorFlowReport)
        case regions(SwiftErrorRegionReport)
        case outcomeWitnesses(SwiftOutcomeReadResult)
        /// Whole-input rejection by loader or adapter, with the exact typed code.
        case rejected(code: String)
    }
    var census: AIRSCensus?
    var outcome: Outcome
    /// Admitted function intervals from the native request, in order (empty when rejected).
    var admittedIntervals: [SwiftErrorFlowFunction]
    var model: AIRSReadModel
    var modelID: String
}

enum AIRSSwiftRunner {
    /// Loader pass, native adapter once on the full request, then the selected analyzer and its requested candidate producer.
    static func live(_ input: AIRSCapturedInput, _ model: AIRSReadModel) -> AIRSSwiftRawResult {
        let modelID = model.modelID(for: AIRSMCPReads.swiftErrorCommand)
        let binary: LoadedBinary
        do {
            binary = try MachOBinaryLoader().load(retainedBytes: input.bytes, sourceURL: input.sourceURL,
                verifiedIdentity: input.identity, layout: input.layout, integrity: input.integrity)
        } catch {
            return .init(census: nil, outcome: .rejected(code: AIRSCaptureFailure(describing: error).code),
                         admittedIntervals: [], model: model, modelID: modelID)
        }
        let census = AIRSCensus(binary: binary)
        let request: SwiftErrorFlowRequest
        do { request = try SwiftErrorFlowNativeAdapter.request(binary: binary) }
        catch let error as SwiftErrorFlowAdapterError {
            return .init(census: census, outcome: .rejected(code: error.code), admittedIntervals: [], model: model, modelID: modelID)
        } catch {
            return .init(census: census, outcome: .rejected(code: "adapter_error"), admittedIntervals: [], model: model, modelID: modelID)
        }
        return analyze(request: request, census: census, model: model)
    }

    /// Same post-adapter seam used by the live retained-input worker. No projection or paging here.
    static func analyze(request: SwiftErrorFlowRequest, census: AIRSCensus?,
                        model: AIRSReadModel) -> AIRSSwiftRawResult {
        let modelID = model.modelID(for: AIRSMCPReads.swiftErrorCommand)
        switch model {
        case .outcomeWitnessV2:
            let edges = SwiftErrorFlowAnalyzer.analyze(request, model: .nativeV1)
            let retained = SwiftOutcomeReadBridge.build(request: request, edgeReport: edges)
            return .init(census: census, outcome: .outcomeWitnesses(retained),
                         admittedIntervals: request.functions, model: model, modelID: modelID)
        case .regionsV1:
            return .init(census: census, outcome: .regions(SwiftErrorRegionAnalyzer.analyze(request)),
                         admittedIntervals: request.functions, model: model, modelID: modelID)
        case .registerCopiesV2:
            return .init(census: census, outcome: .edges(SwiftErrorFlowAnalyzer.analyze(request, model: .registerCopiesV2)),
                         admittedIntervals: request.functions, model: model, modelID: modelID)
        default:
            return .init(census: census, outcome: .edges(SwiftErrorFlowAnalyzer.analyze(request, model: .nativeV1)),
                         admittedIntervals: request.functions, model: model, modelID: modelID)
        }
    }
}

/// Model-aware sibling of `SwiftErrorFlowCoordinator`. One physical worker; same key+model callers share
/// one in-flight task; a different model or key while the worker is occupied is refused, never queued.
/// A result is published only to the ticket that is still current for the same key and model.
@MainActor
final class AIRSSwiftReadCoordinator {
    typealias Run = @Sendable (AIRSCapturedInput, AIRSReadModel) -> AIRSSwiftRawResult
    static let maximumCachedResults = 4

    enum Failure: Error, Equatable { case busy, deadline, cancelled, superseded }

    private final class Flight {
        let key: SwiftErrorFlowSourceKey
        let model: AIRSReadModel
        let ticket = UUID()
        var waiters = 0
        var abandoned = false
        /// True until the synchronous work really returns.
        var running = true
        var monitor: Task<AIRSSwiftRawResult?, Never>?
        init(key: SwiftErrorFlowSourceKey, model: AIRSReadModel) { self.key = key; self.model = model }
    }

    private var flight: Flight?
    private var cached: [(key: SwiftErrorFlowSourceKey, result: AIRSSwiftRawResult)] = []
    private(set) var publishedCount = 0
    private(set) var suppressedCount = 0
    private(set) var runCount = 0

    func cachedResult(key: SwiftErrorFlowSourceKey, model: AIRSReadModel) -> AIRSSwiftRawResult? {
        cached.first { $0.key == key && $0.result.model == model }?.result
    }

    var isOccupied: Bool { flight?.running == true }

    /// Drop every cached result and orphan any running ticket (source or installation changed).
    func invalidate() {
        cached.removeAll()
        if let flight { flight.abandoned = true }
    }

    func result(key: SwiftErrorFlowSourceKey, model: AIRSReadModel, input: AIRSCapturedInput,
                deadlineMillis: Int, run: @escaping Run) async -> Result<AIRSSwiftRawResult, Failure> {
        if let hit = cachedResult(key: key, model: model) { return .success(hit) }
        let active: Flight
        if let current = flight, current.running {
            guard current.key == key, current.model == model, !current.abandoned else { return .failure(.busy) }
            active = current
        } else {
            active = Flight(key: key, model: model)
            flight = active
            runCount += 1
            let work = Task.detached(priority: .userInitiated) { run(input, model) }
            active.monitor = Task { @MainActor [weak self] in
                let value = await work.value
                active.running = false
                guard let self, !active.abandoned, self.flight === active, value.model == active.model else {
                    self?.suppressedCount += 1
                    return nil
                }
                self.cached.append((key, value))
                if self.cached.count > Self.maximumCachedResults { self.cached.removeFirst() }
                self.publishedCount += 1
                return value
            }
        }
        active.waiters += 1
        let monitor = active.monitor!
        let outcome = await airsAwait(deadlineMillis: deadlineMillis) { await monitor.value }
        active.waiters -= 1
        switch outcome {
        case .success(let value):
            if let value { return .success(value) }
            return .failure(.superseded)
        case .failure(let failure):
            // Only a cancellation orphans the flight. A deadline leaves it live: the detached work keeps
            // running, so a retry with the same key and model joins it and the finished result is cached.
            if failure != .deadline, active.waiters == 0 { active.abandoned = true }
            return .failure(failure == .deadline ? .deadline : .cancelled)
        }
    }
}
