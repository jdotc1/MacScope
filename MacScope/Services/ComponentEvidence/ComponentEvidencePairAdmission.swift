import Foundation

extension ComponentEvidence {
    /// Input-only authority. Selections are never retained by an admitted pair.
    struct PairSelection {
        let url: URL
        let providerIdentity: ProviderCaptureIdentity?

        init(url: URL, providerIdentity: ProviderCaptureIdentity? = nil) {
            self.url = url
            self.providerIdentity = providerIdentity
        }
    }

    struct CapturedPairEvidence: Sendable {
        let capture: CaptureResult
        let attachment: SignatureEvidenceAttachment

        fileprivate init(capture: CaptureResult, attachment: SignatureEvidenceAttachment) {
            self.capture = capture
            self.attachment = attachment
        }
    }

    /// Charges cover the shared header ledger, not total I/O or retained bytes.
    struct PairWork: Sendable, Equatable {
        let jointHeaderLimit: Int
        let previousHeaderBytesUsed: Int
        /// Nil means no second capture; zero is an actual returned charge.
        let currentHeaderBytesUsed: Int?
        var headerBytesUsed: Int { previousHeaderBytesUsed + (currentHeaderBytesUsed ?? 0) }
    }

    struct AdmittedPair: Sendable {
        private let backing: [CapturedPairEvidence]
        private let previousIndex: Int
        private let currentIndex: Int
        let binding: PairBinding
        let aliasDecision: AliasDecision
        let previousProviderIdentity: ProviderCaptureIdentity?
        let currentProviderIdentity: ProviderCaptureIdentity?
        let work: PairWork

        var previous: CapturedPairEvidence { backing[previousIndex] }
        var current: CapturedPairEvidence { backing[currentIndex] }
        var backingCount: Int { backing.count }

        fileprivate init(backing: [CapturedPairEvidence], currentIndex: Int,
                         binding: PairBinding, aliasDecision: AliasDecision,
                         previousProviderIdentity: ProviderCaptureIdentity?,
                         currentProviderIdentity: ProviderCaptureIdentity?, work: PairWork) {
            self.backing = backing
            previousIndex = 0
            self.currentIndex = currentIndex
            self.binding = binding
            self.aliasDecision = aliasDecision
            self.previousProviderIdentity = previousProviderIdentity
            self.currentProviderIdentity = currentProviderIdentity
            self.work = work
        }
    }

    typealias PairFaultInjector = (ComponentEvidenceSecurityDelta.Side, Operation, PathRange) -> Int32?
    typealias PairChooser = (LiveComponentInventory, SessionID) -> [CaptureRequest]

    /// A call-local test seam. Production admission always delegates to capture.
    typealias PairCaptureExecutor = (ComponentEvidenceSecurityDelta.Side, URL, BundleDiscovery.Limits,
                                    FaultInjector, SignatureSink?, PairChooser) throws -> CaptureResult

    /// Construction observation only; no observer is stored in the returned value.
    enum PairAdmissionEvent: Equatable {
        case attachmentBuilt(ComponentEvidenceSecurityDelta.Side)
        case attachmentBound(ComponentEvidenceSecurityDelta.Side)
        case sideReady(ComponentEvidenceSecurityDelta.Side)
        case willCommit
    }

    /// Ordered lexical captures, with one atomic publication and no filesystem-wide snapshot claim.
    static func admitPair(previous: PairSelection, current: PairSelection,
                          owner: AnyObject?, installation: UUID?,
                          limits: BundleDiscovery.Limits = BundleDiscovery.Limits(),
                          fault: PairFaultInjector? = nil,
                          choose: PairChooser) throws -> AdmittedPair {
        try _admitPair(previous: previous, current: current, owner: owner, installation: installation,
                       limits: limits, fault: fault, choose: choose)
    }

    static func _admitPair(previous: PairSelection, current: PairSelection,
                           owner: AnyObject?, installation: UUID?,
                           limits: BundleDiscovery.Limits = BundleDiscovery.Limits(),
                           fault: PairFaultInjector? = nil,
                           execute: PairCaptureExecutor = { _, selection, limits, fault, sink, choose in
                               try capture(selection: selection, limits: limits, fault: fault,
                                           signatureSink: sink, choose: choose)
                           },
                           observe: (PairAdmissionEvent) -> Void = { _ in },
                           choose: PairChooser) throws -> AdmittedPair {
        typealias Delta = ComponentEvidenceSecurityDelta
        try pairCheckCancellation()
        guard let owner, let installation else {
            throw try Delta.Refusal(code: .sourceStale, underlyingKind: .stale)
        }
        let binding = PairBinding(ownerID: ObjectIdentifier(owner), installationID: installation)
        let providerSame = previous.providerIdentity != nil && previous.providerIdentity == current.providerIdentity
        let first = try pairCapture(selection: previous, side: .previous, limits: limits, fault: fault,
                                    execute: execute, observe: observe, choose: choose)
        let previousEvidence: CapturedPairEvidence
        switch first {
        case .available(let value): previousEvidence = value
        case .failed(let failure, let provenEarly):
            try pairCheckCancellation()
            guard !providerSame, provenEarly else { throw try pairRefusal(failure) }
            // The proven prefix precedes ledger creation. This is not an inferred zero charge
            // for an arbitrary throw. Even a successful current side cannot publish a pair.
            let second = try pairCapture(selection: current, side: .current, limits: limits, fault: fault,
                                         execute: execute, observe: observe, choose: choose)
            try pairCheckCancellation()
            if case .failed(let currentFailure, _) = second {
                throw try Delta.Refusal(code: .previousUnavailable,
                                         sideFailures: [failure, currentFailure])
            }
            throw try pairRefusal(failure)
        }

        let backing: [CapturedPairEvidence]
        let currentIndex: Int
        let decision: AliasDecision
        let currentCharge: Int?
        if providerSame {
            backing = [previousEvidence]
            currentIndex = 0
            decision = .providerSame
            currentCharge = nil
        } else {
            try pairCheckCancellation()
            let remainder = limits.headerBytes - previousEvidence.capture.headerBytesUsed
            let currentLimits = BundleDiscovery.Limits(entries: limits.entries, depth: limits.depth,
                                                       candidates: limits.candidates, headerBytes: remainder)
            // Do not round a sub-minimum remainder up: capture performs its own validation.
            let second = try pairCapture(selection: current, side: .current, limits: currentLimits,
                                         fault: fault, execute: execute, observe: observe, choose: choose)
            let currentEvidence: CapturedPairEvidence
            switch second {
            case .available(let value): currentEvidence = value
            case .failed(let failure, _):
                try pairCheckCancellation()
                throw try pairRefusal(failure)
            }
            try pairCheckCancellation()
            currentCharge = currentEvidence.capture.headerBytesUsed
            if previousEvidence.capture.rootIdentity == currentEvidence.capture.rootIdentity {
                if previous.providerIdentity != nil, current.providerIdentity != nil {
                    throw try Delta.Refusal(code: .ambiguousSelection)
                }
                backing = [previousEvidence]
                currentIndex = 0
                decision = .rootsCoalesced
            } else {
                backing = [previousEvidence, currentEvidence]
                currentIndex = 1
                decision = .distinct
            }
        }
        let work = PairWork(jointHeaderLimit: limits.headerBytes,
                            previousHeaderBytesUsed: previousEvidence.capture.headerBytesUsed,
                            currentHeaderBytesUsed: currentCharge)
        observe(.willCommit)
        try pairCheckCancellation()
        return AdmittedPair(backing: backing, currentIndex: currentIndex, binding: binding,
                            aliasDecision: decision, previousProviderIdentity: previous.providerIdentity,
                            currentProviderIdentity: current.providerIdentity, work: work)
    }

    private enum PairAttempt {
        case available(CapturedPairEvidence)
        case failed(ComponentEvidenceSecurityDelta.ReadSideFailure, provenEarly: Bool)
    }

    /// Only the exact initial descriptor prefix can prove that no ledger existed.
    private enum PairCapturePhase {
        case beforeOperations, openingRoot, initialRootStat, pastPrefix

        mutating func record(_ operation: Operation, _ range: PathRange) {
            switch (self, operation, range) {
            case (.beforeOperations, .openRoot, .wholeRoot): self = .openingRoot
            case (.openingRoot, .statDescriptor, .wholeRoot): self = .initialRootStat
            default: self = .pastPrefix
            }
        }

        func provesEarly(_ error: Error) -> Bool {
            guard let error = error as? EvidenceError else { return false }
            switch (self, error) {
            case (.beforeOperations, .invalidLimits), (.beforeOperations, .invalidSelection),
                 (.openingRoot, .io(.openRoot, _, .wholeRoot)),
                 (.initialRootStat, .io(.statDescriptor, _, .wholeRoot)):
                return true
            default: return false
            }
        }
    }

    private static func pairCapture(selection: PairSelection, side: ComponentEvidenceSecurityDelta.Side,
                                    limits: BundleDiscovery.Limits, fault: PairFaultInjector?,
                                    execute: PairCaptureExecutor, observe: (PairAdmissionEvent) -> Void,
                                    choose: PairChooser) throws -> PairAttempt {
        var phase = PairCapturePhase.beforeOperations
        var entries: [(componentID: RelativePath, evidence: SignatureEvidence)] = []
        var failures: [SignatureCaptureFailure] = []
        var sinkCancelled = false
        let sink: SignatureSink = { path, result in
            switch result {
            case .success(let evidence): entries.append((path, evidence))
            case .failure(let error):
                failures.append(SignatureCaptureFailure(componentID: path, error: error))
                if case .cancelled = error { sinkCancelled = true }
            }
        }
        let captured: CaptureResult
        do {
            captured = try withoutActuallyEscaping(choose) { escapingChoose in
                try execute(side, selection.url, limits, { operation, range in
                    phase.record(operation, range)
                    return fault?(side, operation, range)
                }, sink, { live, session in
                    phase = .pastPrefix
                    return escapingChoose(live, session)
                })
            }
        } catch {
            if Task.isCancelled || sinkCancelled || error is CancellationError
                || (error as? EvidenceError)?.kind == .cancelled {
                throw try pairCancelled(side: side)
            }
            let early = phase.provesEarly(error)
            let kind = pairUnderlying(error, initialFailure: early)
            return .failed(pairSideFailure(side, kind), provenEarly: early)
        }
        if captured.inventory.scope.completion == .cancelled || sinkCancelled
            || pairIssues(captured.inventory).contains(where: { $0.kind == .cancelled })
            || captured.observations.contains(where: { $0.issue?.kind == .cancelled }) {
            throw try pairCancelled(side: side)
        }
        // A completed synchronous return is a pair boundary. Cancellation recorded in the
        // returned evidence remains side-attributed; task-only cancellation here is global.
        if Task.isCancelled {
            throw try pairCancelled(side: captured.inventory.isComplete ? nil : side)
        }
        guard captured.inventory.isComplete else {
            return .failed(pairSideFailure(side, pairPartialKind(captured.inventory)), provenEarly: false)
        }
        let attachment: SignatureEvidenceAttachment
        do {
            attachment = try SignatureEvidenceAttachment(inventoryID: captured.inventory.id,
                                                          entries: entries, failures: failures)
            observe(.attachmentBuilt(side))
            try attachment.bind(to: captured.inventory)
            observe(.attachmentBound(side))
        } catch {
            try pairCheckCancellation()
            return .failed(pairSideFailure(side, .bindingMismatch), provenEarly: false)
        }
        guard captured.rootIdentity != nil else {
            try pairCheckCancellation()
            return .failed(pairSideFailure(side, .bindingMismatch), provenEarly: false)
        }
        // The real capture ledger guarantees this range. Also reject malformed receipts at
        // the internal executor seam rather than allowing subtraction or addition overflow.
        guard captured.headerBytesUsed >= 0, captured.headerBytesUsed <= limits.headerBytes else {
            try pairCheckCancellation()
            return .failed(pairSideFailure(side, .bindingMismatch), provenEarly: false)
        }
        observe(.sideReady(side))
        try pairCheckCancellation()
        return .available(CapturedPairEvidence(capture: captured, attachment: attachment))
    }

    private static func pairIssues(_ inventory: ComponentInventory) -> [EvidenceIssue] {
        inventory.scope.issues + inventory.components.sorted { $0.path < $1.path }.flatMap(\.issues)
    }

    private static func pairPartialKind(_ inventory: ComponentInventory) -> ComponentEvidenceSecurityDelta.UnderlyingKind {
        let issues = pairIssues(inventory)
        let limitStates: Set<ExclusionState> = [.entryLimit, .depthLimit, .candidateLimit, .headerLimit, .pathLimit]
        if issues.contains(where: { $0.kind == .budgetExceeded })
            || inventory.scope.exclusionOverflow != nil || inventory.scope.issueOverflow != nil
            || inventory.components.contains(where: { $0.issueOverflow != nil })
            || inventory.scope.exclusions.contains(where: { limitStates.contains($0.state) }) {
            return .budget
        }
        if let first = issues.first { return pairUnderlying(first.error, initialFailure: false) }
        for exclusion in inventory.scope.exclusions {
            switch exclusion.state {
            case .unreadable: return .readFailed
            case .changed: return .stale
            default: continue
            }
        }
        return .unavailable
    }

    private static func pairUnderlying(_ error: Error, initialFailure: Bool) -> ComponentEvidenceSecurityDelta.UnderlyingKind {
        guard let error = error as? EvidenceError else { return .readFailed }
        switch error {
        case .invalidSelection, .principalUnavailable, .principalUnresolved: return .unavailable
        case .invalidLimits, .budgetExceeded: return .budget
        case .io: return initialFailure ? .unavailable : .readFailed
        case .shortRead: return .readFailed
        case .changedInput, .staleCapability, .sourceMismatch: return .stale
        case .unsafePath, .malformedHeader, .malformedMetadata, .invalidInventory: return .malformed
        case .invalidObservation, .architectureMismatch, .unknownComponent, .unknownMatch: return .bindingMismatch
        case .cancelled: return .cancelled
        }
    }

    private static func pairSideFailure(_ side: ComponentEvidenceSecurityDelta.Side,
                                        _ kind: ComponentEvidenceSecurityDelta.UnderlyingKind)
        -> ComponentEvidenceSecurityDelta.ReadSideFailure {
        ComponentEvidenceSecurityDelta.ReadSideFailure(side: side,
            code: side == .previous ? .previousUnavailable : .currentUnavailable, underlyingKind: kind)
    }

    private static func pairRefusal(_ failure: ComponentEvidenceSecurityDelta.ReadSideFailure)
        throws -> ComponentEvidenceSecurityDelta.Refusal {
        try ComponentEvidenceSecurityDelta.Refusal(code: failure.code, side: failure.side,
                                                    underlyingKind: failure.underlyingKind, sideFailures: [failure])
    }

    private static func pairCancelled(side: ComponentEvidenceSecurityDelta.Side? = nil)
        throws -> ComponentEvidenceSecurityDelta.Refusal {
        let failures = side.map {
            [ComponentEvidenceSecurityDelta.ReadSideFailure(side: $0, code: .cancelled, underlyingKind: .cancelled)]
        } ?? []
        return try ComponentEvidenceSecurityDelta.Refusal(code: .cancelled, side: side,
                                                           underlyingKind: .cancelled, sideFailures: failures)
    }

    private static func pairCheckCancellation() throws {
        if Task.isCancelled { throw try pairCancelled() }
    }
}
