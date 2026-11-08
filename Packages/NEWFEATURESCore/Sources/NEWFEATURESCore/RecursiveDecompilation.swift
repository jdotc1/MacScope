import Foundation

public enum NEWFEATURESDecompilerBackend: String, Sendable {
    case nativeSleigh
    case macIRFallback
    case unavailable
}

public enum NEWFEATURESFunctionOutcome: String, Sendable {
    case nativeComplete
    case nativePartial
    case fallback
    case unavailable
    case failed
    case stale
    case oversized
    case deadlineExceeded
}

public struct NEWFEATURESDecompileRequest: Sendable {
    public let function: NEWFEATURESFunctionKey
    public let maximumUTF8Bytes: Int
    public let deadline: ContinuousClock.Instant
}

/// The provider must echo the exact source identity observed by the worker and must
/// distinguish native SLEIGH from MacIR. A caller-generated echo alone is insufficient:
/// the adapter must bind this to the worker's actual source and revalidate in the app.
public struct NEWFEATURESDecompileResponse: Sendable {
    public let function: NEWFEATURESFunctionKey
    public let backend: NEWFEATURESDecompilerBackend
    public let text: String?
    public let complete: Bool
    public let refusalCode: String?
    /// Independently returned native-provider receipt. App must validate this
    /// against NativeProviderExportValidation; a request echo is never proof.
    public let workerReceipt: NEWFEATURESNativeWorkerReceipt?
    public let fallbackReceipt: NEWFEATURESMacIRReceipt?

    public init(
        function: NEWFEATURESFunctionKey,
        backend: NEWFEATURESDecompilerBackend,
        text: String?,
        complete: Bool,
        refusalCode: String? = nil,
        workerReceipt: NEWFEATURESNativeWorkerReceipt? = nil,
        fallbackReceipt: NEWFEATURESMacIRReceipt? = nil
    ) {
        self.function = function
        self.backend = backend
        self.text = text
        self.complete = complete
        self.refusalCode = refusalCode
        self.workerReceipt = workerReceipt
        self.fallbackReceipt = fallbackReceipt
    }
}

public struct NEWFEATURESNativeWorkerReceipt: Sendable, Equatable {
    public let observedFunction: NEWFEATURESFunctionKey
    public let artifactID: UUID
    public let nativeFunctionID: UUID
    public let requestDigestSHA256: String

    public init(
        observedFunction: NEWFEATURESFunctionKey,
        artifactID: UUID,
        nativeFunctionID: UUID,
        requestDigestSHA256: String
    ) throws {
        guard requestDigestSHA256.utf8.count == 64,
              requestDigestSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw NEWFEATURESError.malformedFact("invalid worker request digest") }
        self.observedFunction = observedFunction
        self.artifactID = artifactID
        self.nativeFunctionID = nativeFunctionID
        self.requestDigestSHA256 = requestDigestSHA256
    }
}

/// App-only MacIR provenance; neither scripting input nor model text may mint
/// a fallback receipt. The source checker validates this against immutable
/// MacIR artifact/snapshot authority separately from native XPC receipts.
public struct NEWFEATURESMacIRReceipt: Sendable, Equatable {
    public let observedFunction: NEWFEATURESFunctionKey
    public let macIRArtifactID: UUID
    public let sourceSHA256: String

    public init(observedFunction: NEWFEATURESFunctionKey, macIRArtifactID: UUID, sourceSHA256: String) throws {
        guard sourceSHA256 == observedFunction.image.sha256 else {
            throw NEWFEATURESError.invalidImageIdentity
        }
        self.observedFunction = observedFunction
        self.macIRArtifactID = macIRArtifactID
        self.sourceSHA256 = sourceSHA256
    }
}

public protocol NEWFEATURESNativeDecompiling: Sendable {
    /// Production provider MUST bound its worker/XPC operation by request.deadline
    /// and invalidate unresponsive workers. The coordinator's deadline race
    /// bounds its own wait, but cannot kill a stuck XPC worker on its own.
    func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse
}

/// The app re-observes its current immutable image/revision authority before each
/// operation and after each worker await. Workers do not implement this authority.
public protocol NEWFEATURESSourceChecking: Sendable {
    func isCurrent(_ admission: NEWFEATURESLedgerAdmission) async -> Bool
    /// Host-only independent check of source, artifact, native UUID and
    /// request digest via existing NativeProviderExportValidation.
    func admits(_ response: NEWFEATURESDecompileResponse,
                for request: NEWFEATURESDecompileRequest,
                admission: NEWFEATURESLedgerAdmission) async -> Bool
}

public struct NEWFEATURESFunctionResult: Sendable {
    public let function: NEWFEATURESFunctionKey
    public let outcome: NEWFEATURESFunctionOutcome
    public let backend: NEWFEATURESDecompilerBackend
    public let text: String?
    public let reason: String?
}

public enum NEWFEATURESBatchTermination: String, Sendable {
    case exhaustedObservedPlan
    case traversalLimited
    case sourceChanged
    case cancelled
    case deadlineExceeded
    case outputLimit
}

public struct NEWFEATURESRecursiveReport: Sendable {
    public let admission: NEWFEATURESLedgerAdmission
    public let traversal: NEWFEATURESTraversalResult
    public let results: [NEWFEATURESFunctionResult]
    public let termination: NEWFEATURESBatchTermination
    /// An *internal* final ledger read, not authorization to publish forever.
    /// MCP/GUI must still recheck this admission at the actual publication edge.
    public let internallyValidatedAtReturn: Bool

    public var acceptedNativeFunctionCount: Int {
        internallyValidatedAtReturn ? results.filter { $0.outcome == .nativeComplete }.count : 0
    }
}

/// Serializes a native-worker batch and refuses reuse while another batch is outstanding.
/// The XPC adapter must enforce its own hard per-request timeout: an uncooperative
/// native process cannot be preempted merely by checking ContinuousClock after await.
public actor NEWFEATURESRecursiveCoordinator {
    private var active = false
    private var workerRecoveryRequired = false

    public init() {}

    public func execute(
        root: NEWFEATURESFunctionKey,
        graph: NEWFEATURESGraphSnapshot,
        admission: NEWFEATURESLedgerAdmission,
        budget: NEWFEATURESReadBudget,
        provider: any NEWFEATURESNativeDecompiling,
        sourceChecker: any NEWFEATURESSourceChecking
    ) async throws -> NEWFEATURESRecursiveReport {
        guard !active else { throw NEWFEATURESError.operationAlreadyActive }
        guard !workerRecoveryRequired else { throw NEWFEATURESError.nativeWorkerNeedsRecovery }
        guard root.image == admission.image,
              graph.functions.allSatisfy({ $0.image == admission.image }) else {
            throw NEWFEATURESError.invalidImageIdentity
        }
        active = true
        defer { active = false }

        let traversal = try NEWFEATURESCallGraphTraversal.expand(
            root: root, graph: graph, budget: budget,
            operation: NEWFEATURESGraphOperation(budget: budget)
        )
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(budget.maxElapsedSeconds))
        var results: [NEWFEATURESFunctionResult] = []
        var totalOutputBytes = 0
        var termination: NEWFEATURESBatchTermination =
            traversal.isCompleteWithinObservedGraph ? .exhaustedObservedPlan : .traversalLimited

        batch: for function in traversal.orderedFunctions {
            if Task.isCancelled {
                termination = .cancelled
                break
            }
            if clock.now >= deadline {
                termination = .deadlineExceeded
                break
            }
            guard await sourceChecker.isCurrent(admission) else {
                termination = .sourceChanged
                break
            }
            if clock.now >= deadline {
                termination = .deadlineExceeded
                break
            }

            let request = NEWFEATURESDecompileRequest(
                function: function,
                maximumUTF8Bytes: budget.maxOutputBytesPerFunction,
                deadline: deadline
            )
            let response: NEWFEATURESDecompileResponse
            switch await NEWFEATURESDeadlineRace.run(request: request, provider: provider) {
            case .timedOut:
                // An uncooperative detached provider may still be alive.
                // Poison this coordinator until the app retires this object
                // AFTER NativePseudocodeBatchSession invalidates the XPC worker.
                workerRecoveryRequired = true
                results.append(Self.result(function, .deadlineExceeded, .unavailable, nil, "worker deadline"))
                termination = .deadlineExceeded
                break batch
            case .cancelled:
                termination = .cancelled
                break batch
            case .completed(let completed):
                response = completed
            }

            if Task.isCancelled {
                termination = .cancelled
                break
            }
            if clock.now >= deadline {
                results.append(Self.result(function, .deadlineExceeded, .unavailable, nil, "batch deadline"))
                termination = .deadlineExceeded
                break
            }
            guard await sourceChecker.isCurrent(admission) else {
                results.append(Self.result(function, .stale, .unavailable, nil, "source changed after await"))
                termination = .sourceChanged
                break
            }
            if clock.now >= deadline {
                termination = .deadlineExceeded
                break
            }
            guard response.function == function else {
                results.append(Self.result(function, .stale, .unavailable, nil, "worker identity mismatch"))
                termination = .sourceChanged
                break
            }
            if response.text != nil {
                let hasBackendProof: Bool
                switch response.backend {
                case .nativeSleigh:
                    hasBackendProof = response.workerReceipt?.observedFunction == function
                case .macIRFallback:
                    hasBackendProof = response.fallbackReceipt?.observedFunction == function
                case .unavailable:
                    hasBackendProof = false
                }
                guard hasBackendProof,
                      await sourceChecker.admits(response, for: request, admission: admission) else {
                    results.append(Self.result(function, .stale, .unavailable, nil, "unattested native source"))
                    termination = .sourceChanged
                    break
                }
                if clock.now >= deadline {
                    termination = .deadlineExceeded
                    break
                }
            }
            if let text = response.text,
               text.utf8.count > budget.maxOutputBytesPerFunction {
                results.append(Self.result(function, .oversized, response.backend, nil, "oversized worker output"))
                continue
            }
            guard let text = response.text, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                let outcome: NEWFEATURESFunctionOutcome =
                    response.backend == .unavailable ? .unavailable : .failed
                results.append(Self.result(
                    function, outcome, response.backend, nil, Self.safeCode(response.refusalCode)
                ))
                continue
            }
            let bytes = text.utf8.count
            guard bytes <= budget.maxTotalUTF8Bytes - totalOutputBytes else {
                results.append(Self.result(function, .oversized, response.backend, nil, "aggregate output limit"))
                termination = .outputLimit
                break
            }
            let outcome: NEWFEATURESFunctionOutcome
            switch response.backend {
            case .nativeSleigh:
                outcome = response.complete ? .nativeComplete : .nativePartial
            case .macIRFallback:
                outcome = .fallback
            case .unavailable:
                results.append(Self.result(function, .unavailable, .unavailable, nil, "invalid unavailable payload"))
                continue
            }
            results.append(Self.result(function, outcome, response.backend, text, nil))
            totalOutputBytes += bytes
        }
        // Final coherent read of the app's Phase2 ledger. A source failure
        // invalidates ALL previous text in the batch, not merely the last item.
        let finalValid = await sourceChecker.isCurrent(admission)
        if !finalValid { termination = .sourceChanged }
        else if clock.now >= deadline && termination != .sourceChanged &&
                    termination != .deadlineExceeded {
            termination = .deadlineExceeded
        }
        if termination == .sourceChanged {
            results = results.map {
                Self.result($0.function, .stale, .unavailable, nil, "source admission revoked")
            }
        }
        return NEWFEATURESRecursiveReport(
            admission: admission, traversal: traversal, results: results,
            termination: termination, internallyValidatedAtReturn: finalValid && termination != .sourceChanged
        )
    }

    private static func safeCode(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty, raw.utf8.count <= 128,
              raw.utf8.allSatisfy({ $0 >= 32 && $0 < 127 })
        else { return "worker-unavailable" }
        return raw
    }

    private static func result(
        _ function: NEWFEATURESFunctionKey,
        _ outcome: NEWFEATURESFunctionOutcome,
        _ backend: NEWFEATURESDecompilerBackend,
        _ text: String?,
        _ reason: String?
    ) -> NEWFEATURESFunctionResult {
        NEWFEATURESFunctionResult(function: function, outcome: outcome, backend: backend, text: text, reason: reason)
    }
}
