import Foundation
import Observation

/// Transient state for saved reports only. No store writer, navigation, analysis execution or
/// annotation-transfer capability is held here. Rebinding a document fences every publication.
@MainActor
@Observable
final class VersionCompareAIRSEvidenceViewModel {
    typealias Worker = @Sendable (UnwindAuditReport, UnwindAuditReport, [FunctionVersionManualPin])
        async throws -> UnwindAuditComparison
    enum Phase: Equatable { case idle, running, ready, failed(String) }

    private(set) var inventory: VersionCompareAIRSEvidenceInventory = .empty
    private(set) var baselineID: UUID?
    private(set) var currentID: UUID?
    private(set) var phase: Phase = .idle
    private(set) var comparison: UnwindAuditComparison?
    private(set) var orderedChanges: [UnwindAuditMatchedChange] = []
    private(set) var pinError: String?
    @ObservationIgnored private var boundEnvelope: AIRSEvidenceEnvelope?
    @ObservationIgnored private var workspaceID: UUID?
    @ObservationIgnored private var installationID: UUID?
    @ObservationIgnored private var generation: UInt64 = 0
    @ObservationIgnored private var publication: Task<Void, Never>?
    @ObservationIgnored private var computation: Task<UnwindAuditComparison, any Error>?
    @ObservationIgnored private let worker: Worker

    init(worker: @escaping Worker = { old, new, pins in
        try UnwindAuditComparator.compare(baseline: old, current: new, pins: pins)
    }) { self.worker = worker }

    var baseline: VersionCompareAIRSEvidenceEntry? { inventory.nativeEntries.first { $0.id == baselineID } }
    var current: VersionCompareAIRSEvidenceEntry? { inventory.nativeEntries.first { $0.id == currentID } }
    var canCompare: Bool { baseline != nil && current != nil && baselineID != currentID }

    func bind(_ envelope: AIRSEvidenceEnvelope, workspaceID: UUID, installationID: UUID) {
        guard boundEnvelope != envelope || self.workspaceID != workspaceID || self.installationID != installationID else { return }
        let replacement = self.workspaceID != workspaceID || self.installationID != installationID
        cancel()
        self.workspaceID = workspaceID
        self.installationID = installationID
        boundEnvelope = envelope
        do {
            inventory = try VersionCompareAIRSEvidenceInventory.build(envelope, workspaceID: workspaceID)
            if replacement || baseline == nil { baselineID = inventory.nativeEntries.first?.id }
            if replacement || current == nil || currentID == baselineID {
                currentID = inventory.nativeEntries.first { $0.id != baselineID }?.id
            }
        } catch {
            inventory = .empty
            baselineID = nil
            currentID = nil
            phase = .failed(error.localizedDescription)
        }
    }

    func selectBaseline(_ id: UUID?) {
        guard id != baselineID else { return }
        cancel()
        baselineID = inventory.nativeEntries.contains { $0.id == id } ? id : nil
    }

    func selectCurrent(_ id: UUID?) {
        guard id != currentID else { return }
        cancel()
        currentID = inventory.nativeEntries.contains { $0.id == id } ? id : nil
    }

    /// Cancellation advances the generation even if the worker ignores cancellation.
    func cancel() {
        generation &+= 1
        computation?.cancel()
        publication?.cancel()
        computation = nil
        publication = nil
        comparison = nil
        orderedChanges = []
        pinError = nil
        phase = .idle
    }

    @discardableResult
    func run() -> Task<Void, Never>? { start(pins: []) }

    func pin(oldID: String, newID: String) {
        guard phase == .ready, let comparison, let old = baseline?.report, let new = current?.report else { return }
        do {
            // The existing resolver enforces unknown/already-matched/conflicting pin rules.
            let matcher = try FunctionVersionMatcher(old: old.findings.map(\.function), new: new.findings.map(\.function))
            let resolved = try matcher.resolve(comparison.matching, pinning: .init(oldID: oldID, newID: newID))
            start(pins: resolved.manualPins)
        } catch { pinError = String(describing: error) }
    }

    @discardableResult
    private func start(pins: [FunctionVersionManualPin]) -> Task<Void, Never>? {
        cancel()
        guard canCompare, let old = baseline?.report, let new = current?.report else { return nil }
        phase = .running
        let token = generation
        let worker = worker
        let job = Task.detached(priority: .userInitiated) { try await worker(old, new, pins) }
        computation = job
        let task = Task { [weak self] in
            let outcome: Result<UnwindAuditComparison, any Error>
            do { outcome = .success(try await job.value) } catch { outcome = .failure(error) }
            guard let self, !Task.isCancelled, self.generation == token else { return }
            self.computation = nil
            self.publication = nil
            switch outcome {
            case .success(let comparison):
                self.comparison = comparison
                self.orderedChanges = comparison.changes.sorted {
                    let left = $0.beforeVerdict == "unresolved" || $0.afterVerdict == "unresolved"
                    let right = $1.beforeVerdict == "unresolved" || $1.afterVerdict == "unresolved"
                    if left != right { return left }
                    if $0.match.oldAddress != $1.match.oldAddress { return $0.match.oldAddress < $1.match.oldAddress }
                    return $0.match.oldID < $1.match.oldID
                }
                self.phase = .ready
            case .failure(let error): self.phase = .failed(error.localizedDescription)
            }
        }
        publication = task
        return task
    }
}
