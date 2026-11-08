import Foundation

/// Stage A raw work counters for startup analysis (item 1326).
///
/// Bounded recorder: a closed set of nonnegative checked-integer totals, one
/// availability state per field, and one analysis lifecycle. No I/O, clock, global,
/// section/round/address-keyed map, or retained data lives here. Only a `complete`
/// field yields a value; unseen, collecting, interrupted and invalid fields are
/// absent (nil), never zero. A reached empty loop is a complete zero. A successful
/// analyze return is not "ready"; the startup gate install keeps that meaning.
final class StartupWorkCounters: @unchecked Sendable {
    enum Field: Int, CaseIterable, Sendable {
        case codeSectionBuilds, decodeCodeSectionRows, sections, codeInstructions
        case discoveryInvocations, sliceCopiesAvoided, sectionCallsAttempted, sectionCallsCompleted
        case symbolNameMapBuilds, sectionStartFilterBuilds, objcCandidateCollections
        case symbolCandidateCollections, swiftCandidateExtractions, swiftReaderCopiedBytes
        case orderedRowRequests, orderedRowBuilds, orderedRowsVisited
        case prologueRowsVisited, branchTargetBuilds, branchTargetRowsVisited
        case recoveryCandidateRowsVisited, recoveryTerminatorTests
        case dataPointerCandidateSetBuilds, afterTerminatorBuilds, afterTerminatorRowsVisited
        case dataPointerBranchTargetBuilds, dataPointerBranchTargetRowsVisited
        case dataPointerCandidatesVisited
        case trampolineRowsVisited, trampolineIndexBuilds, trampolineAfterTerminatorBuilds
        case trampolineAfterTerminatorRowsVisited, trampolineStartsVisited
        case propagationCalls, propagationIndexBuilds, propagationIndexRows
        case propagationInnerRounds, functionsConsidered, successorVisits
        case decodedAddressBuilds, unavailableAddressBuilds, directCallBuilds
        case cacheAdmissions, cacheRefusals, retainedEntriesCurrent, retainedEntriesPeak
        case preparationFallbackDirectCallRequests, preparationFallbackDecodedAddressBuilds
        case preparationFallbackUnavailableBuilds
        case leaderRowsVisited, leaders, ownerQueries, blockRowsVisited, blocks
        case edgeRowsVisited, emittedEdges
        case jumpFunctionsConsidered, jumpFunctionsAccepted, jumpRowSliceCopies, jumpRowsCopied
        case stringRecoveryCalls, stringSectionEntriesVisited, stringRetainedEntriesValidated
        case stringReferencesVisited, stringCandidatesVisited, stringAdditions
        case stringRetainedMergeVisits
        case diagnosticMembershipQueries, diagnosticMembershipComparisons
        case diagnosticSectionRanges, collectorInputInstructions, collectorInputEdges
        case collectorInputXrefs, collectorInputRows, collectorOutputRows
    }

    /// Owner scopes that close a group of fields after their last possible contribution.
    enum Phase: Int, CaseIterable, Sendable {
        case admission, decodeAdmission, setup, codeFilter, discovery, store
        case cfg, jump, string, collector
    }

    enum Availability: Sendable { case unseen, collecting, complete, interrupted, invalid }
    enum AnalysisState: String, Sendable { case notEntered, collecting, completed, cancelled, failed, invalid }
    enum PhaseState: Sendable { case unseen, collecting, completed, interrupted }

    struct Snapshot: Sendable {
        let analysis: AnalysisState
        /// Complete fields only; every other state is absent.
        let values: [Field: Int]
        /// Extension-only misuse count; present only after a terminal valid lifecycle.
        let misuse: Int?
    }

    private let lock = NSLock()
    private var state = AnalysisState.notEntered
    private var values = [Int](repeating: 0, count: Field.allCases.count)
    private var availability = [Availability](repeating: .unseen, count: Field.allCases.count)
    private var phases = [PhaseState](repeating: .unseen, count: Phase.allCases.count)
    private var misuse = 0
    private var misuseOverflow = false

    init() {}

    // MARK: Lifecycle

    /// Starts the single active analysis scope. A reused recorder becomes invalid.
    func beginAnalysis() {
        lock.lock()
        defer { lock.unlock() }
        if state == .notEntered {
            state = .collecting
        } else {
            state = .invalid
            noteMisuseLocked()
        }
    }

    func finishAnalysis(_ outcome: AnalysisAttribution.Outcome) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting else {
            noteMisuseLocked()
            return
        }
        for index in phases.indices where phases[index] == .collecting { phases[index] = .interrupted }
        for index in availability.indices where availability[index] == .collecting {
            availability[index] = .interrupted
        }
        switch outcome {
        case .success: state = .completed
        case .cancelled: state = .cancelled
        case .failed: state = .failed
        }
    }

    // MARK: Mutation (ignored outside the active analysis scope)

    /// Marks an owner scope reached without adding work to any field.
    func enter(_ phase: Phase) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting else { return }
        if phases[phase.rawValue] == .unseen { phases[phase.rawValue] = .collecting }
    }

    /// Marks a field's site as entered, so a reached empty loop closes as zero.
    func begin(_ field: Field) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting else { return }
        guard !rejectClosedPhaseLocked(field) else { return }
        touchLocked(field)
    }

    func add(_ field: Field, _ amount: Int = 1) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting else { return }
        guard !rejectClosedPhaseLocked(field) else { return }
        guard amount >= 0 else {
            noteMisuseLocked()
            return
        }
        touchLocked(field)
        let index = field.rawValue
        guard availability[index] == .collecting else { return }
        let sum = values[index].addingReportingOverflow(amount)
        if sum.overflow {
            availability[index] = .invalid
            noteMisuseLocked()
        } else {
            values[index] = sum.partialValue
        }
    }

    /// Replaces an absolute value (for a store gauge or a derived scalar).
    func set(_ field: Field, _ value: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting, value >= 0 else { return }
        guard !rejectClosedPhaseLocked(field) else { return }
        touchLocked(field)
        let index = field.rawValue
        guard availability[index] == .collecting else { return }
        values[index] = value
    }

    /// The field's entered site did not return normally (early return or throw).
    func interrupt(_ field: Field) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting else { return }
        guard !rejectClosedPhaseLocked(field) else { return }
        if availability[field.rawValue] == .collecting { availability[field.rawValue] = .interrupted }
    }

    /// Store gauges are event values: each completed existing mutation publishes them.
    func publishStoreGauge(current: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting, current >= 0 else { return }
        if isClosedLocked(.store) {
            for field in [Field.retainedEntriesCurrent, .retainedEntriesPeak] { availability[field.rawValue] = .invalid }
            noteMisuseLocked()
            return
        }
        if phases[Phase.store.rawValue] == .unseen { phases[Phase.store.rawValue] = .collecting }
        let now = Field.retainedEntriesCurrent.rawValue
        let peak = Field.retainedEntriesPeak.rawValue
        guard availability[now] != .invalid, availability[peak] != .invalid else { return }
        values[now] = current
        values[peak] = Swift.max(availability[peak] == .complete ? values[peak] : 0, current)
        availability[now] = .complete
        availability[peak] = .complete
    }

    /// Closes an owner scope after its last possible contribution. Reached (begun or
    /// added) fields become complete, including a reached empty loop at zero; fields
    /// whose site was never reached stay unseen and therefore absent.
    func close(_ phase: Phase) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .collecting else { return }
        // A never-reached owner has nothing to close; a repeated close is misuse.
        if phases[phase.rawValue] == .unseen { return }
        guard phases[phase.rawValue] == .collecting else {
            noteMisuseLocked()
            return
        }
        phases[phase.rawValue] = .completed
        for field in Field.allCases where field.phase == phase {
            let index = field.rawValue
            if availability[index] == .collecting { availability[index] = .complete }
        }
    }

    // MARK: Read

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        var complete: [Field: Int] = [:]
        for field in Field.allCases where availability[field.rawValue] == .complete {
            complete[field] = values[field.rawValue]
        }
        let terminal = state == .completed || state == .cancelled || state == .failed
        // A reused (invalid) recorder never reports values from an earlier scope.
        if state == .invalid { return Snapshot(analysis: state, values: [:], misuse: nil) }
        return Snapshot(analysis: state, values: complete,
                        misuse: terminal && !misuseOverflow ? misuse : nil)
    }

    private func touchLocked(_ field: Field) {
        let phase = field.phase.rawValue
        if phases[phase] == .unseen { phases[phase] = .collecting }
        if availability[field.rawValue] == .unseen { availability[field.rawValue] = .collecting }
    }

    private func isClosedLocked(_ phase: Phase) -> Bool {
        phases[phase.rawValue] == .completed || phases[phase.rawValue] == .interrupted
    }

    /// Completion is final: a contribution to a closed owner scope is counted misuse and
    /// invalidates that field instead of being retained or reopening the scope.
    private func rejectClosedPhaseLocked(_ field: Field) -> Bool {
        guard isClosedLocked(field.phase) else { return false }
        availability[field.rawValue] = .invalid
        noteMisuseLocked()
        return true
    }

    private func noteMisuseLocked() {
        let sum = misuse.addingReportingOverflow(1)
        if sum.overflow { misuseOverflow = true } else { misuse = sum.partialValue }
    }
}

extension StartupWorkCounters.Field {
    var name: String { "\(self)" }

    var phase: StartupWorkCounters.Phase {
        switch self {
        case .codeSectionBuilds: return .admission
        case .decodeCodeSectionRows: return .decodeAdmission
        case .sections: return .setup
        case .codeInstructions: return .codeFilter
        case .retainedEntriesCurrent, .retainedEntriesPeak: return .store
        case .leaderRowsVisited, .leaders, .ownerQueries, .blockRowsVisited, .blocks,
             .edgeRowsVisited, .emittedEdges: return .cfg
        case .jumpFunctionsConsidered, .jumpFunctionsAccepted, .jumpRowSliceCopies,
             .jumpRowsCopied: return .jump
        case .stringRecoveryCalls, .stringSectionEntriesVisited, .stringRetainedEntriesValidated,
             .stringReferencesVisited, .stringCandidatesVisited, .stringAdditions,
             .stringRetainedMergeVisits: return .string
        case .diagnosticMembershipQueries, .diagnosticMembershipComparisons,
             .diagnosticSectionRanges, .collectorInputInstructions, .collectorInputEdges,
             .collectorInputXrefs, .collectorInputRows, .collectorOutputRows: return .collector
        default: return .discovery
        }
    }
}
