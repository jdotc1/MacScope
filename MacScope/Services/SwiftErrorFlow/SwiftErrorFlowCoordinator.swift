import Combine
import Foundation

struct SwiftErrorFlowSourceKey: Hashable, Sendable {
    let imageID: UUID
    let slot: ImageSlot
    let generation: UUID
    let documentInstallationID: UUID
    let identity: MachOSliceArtifactIdentity
}

struct SwiftErrorFlowTicket: Hashable, Sendable {
    let id: UUID
    let key: SwiftErrorFlowSourceKey
}

/// Ephemeral review state only. Never added to the document or accepted evidence.
struct SwiftErrorFlowResultState: Sendable {
    enum Phase: Equatable, Sendable { case idle, running, completed, cancelled, failed(String) }
    private(set) var key: SwiftErrorFlowSourceKey?
    private(set) var ticket: SwiftErrorFlowTicket?
    private(set) var phase: Phase = .idle
    private(set) var report: SwiftErrorFlowReport?

    mutating func activate(_ key: SwiftErrorFlowSourceKey?) {
        guard self.key != key else { return }
        self.key = key
        ticket = nil
        report = nil
        phase = .idle
    }

    mutating func begin(_ key: SwiftErrorFlowSourceKey) -> SwiftErrorFlowTicket {
        activate(key)
        let ticket = SwiftErrorFlowTicket(id: UUID(), key: key)
        self.ticket = ticket
        report = nil
        phase = .running
        return ticket
    }

    mutating func cancel() {
        ticket = nil
        report = nil
        phase = .cancelled
    }

    @discardableResult
    mutating func publish(_ report: SwiftErrorFlowReport, for ticket: SwiftErrorFlowTicket) -> Bool {
        guard accepts(ticket) else { return false }
        let identity = ticket.key.identity
        guard report.model == SwiftErrorFlowAnalyzer.model,
              !report.sourceReconstructionAllowed, !report.runtimeReachabilityProven,
              report.slice.artifactSHA256 == identity.selectedSliceSHA256,
              report.slice.sliceByteCount == identity.selectedSliceByteCount,
              report.slice.sliceOffset == 0, report.slice.littleEndian,
              report.slice.cpuType == UInt32(bitPattern: identity.rawCPUType),
              report.slice.cpuSubtype == UInt32(bitPattern: identity.rawCPUSubtype) else {
            fail("The result does not match the captured slice and model.", for: ticket)
            return false
        }
        self.report = report
        self.ticket = nil
        phase = .completed
        return true
    }

    mutating func fail(_ message: String, for ticket: SwiftErrorFlowTicket) {
        guard accepts(ticket) else { return }
        self.ticket = nil
        report = nil
        phase = .failed(message)
    }

    private func accepts(_ ticket: SwiftErrorFlowTicket) -> Bool {
        phase == .running && self.ticket == ticket && key == ticket.key
    }
}

private actor SwiftErrorFlowWorker {
    func analyze(load: @Sendable () throws -> LoadedBinary) throws -> SwiftErrorFlowReport {
        try Task.checkCancellation()
        let request = try SwiftErrorFlowNativeAdapter.request(binary: load())
        try Task.checkCancellation()
        let report = SwiftErrorFlowAnalyzer.analyze(request)
        try Task.checkCancellation()
        return report
    }
}

@MainActor
final class SwiftErrorFlowCoordinator: ObservableObject {
    @Published private(set) var state = SwiftErrorFlowResultState()
    private let worker = SwiftErrorFlowWorker()
    private var task: Task<Void, Never>?

    deinit { task?.cancel() }

    func activate(_ key: SwiftErrorFlowSourceKey?) {
        guard state.key != key else { return }
        task?.cancel()
        task = nil
        state.activate(key)
    }

    func start(key: SwiftErrorFlowSourceKey, load: @escaping @Sendable () throws -> LoadedBinary) {
        task?.cancel()
        let ticket = state.begin(key)
        let worker = worker
        task = Task { [weak self] in
            do {
                let report = try await worker.analyze(load: load)
                try Task.checkCancellation()
                _ = self?.state.publish(report, for: ticket)
            } catch {
                self?.state.fail(String(describing: error), for: ticket)
            }
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        state.cancel()
    }
}
