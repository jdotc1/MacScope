import Foundation
import Observation
import NEWFEATURESCore

/// UI freshness includes selection and the real document session. The service separately
/// carries its original analysis admission to the final synchronous publication boundary.
struct NEWFEATURESCallPathViewContext: Hashable {
    struct Source: Hashable {
        let scene: EditorSceneIdentity
        let sessionID: WorkspaceDocumentSessionID
        let focusedSlot: ImageSlot
        let state: Phase2ReadCurrentState
    }

    let source: Source
    let selection: ImageAddress?

    @MainActor
    static func read(store: WorkspaceStore, session: WorkspaceDocumentSession) -> Self? {
        guard !session.isClosedForWindowClose, !session.isTerminationPreparationActive,
              session.snapshot.documentID == store.documentID,
              session.snapshot.workspaceID == store.workspaceID else { return nil }
        return Self(source: Source(
            scene: EditorSceneIdentity(store: store), sessionID: session.snapshot.sessionID,
            focusedSlot: store.focusedImageSlot,
            state: store.phase2ReadCurrentState(for: store.focusedImageSlot)
        ), selection: store.selectedImageAddress)
    }
}

struct NEWFEATURESCallPathUIRequest {
    let context: NEWFEATURESCallPathViewContext
    let source: UInt64
    let destination: UInt64
    let budget: NEWFEATURESReadBudget
}

struct NEWFEATURESCallPathRow: Identifiable, Equatable {
    let id: UUID
    let address: UInt64
}

/// Owned by the stable document editor, not by a transient result row or graph subtree.
/// A cancelled task keeps its slot until the exact async service call has retired.
@MainActor @Observable
final class NEWFEATURESCallPathPresentation {
    enum Notice: Equatable {
        case invalidAddress, unavailable, analysisRequired, identityUnavailable
        case unsupportedArchitecture, ambiguousFunction, inputLimit, outputLimit
        case cancelled, timedOut, selectionChanged, sourceChanged, hidden
    }

    enum Phase: Equatable {
        case idle, searching, cancelling, finished
        case refused(Notice)
    }

    struct Summary: Equatable {
        let status: NEWFEATURESPathStatus
        let visitedFunctions: Int
        let visitedEdges: Int
        let unresolvedObservations: Int
        let examinedUnverifiedEdges: Int
    }

    typealias Runner = @MainActor (
        NEWFEATURESCallPathUIRequest,
        @escaping @MainActor (NEWFEATURESCallPathDelivery) -> Void
    ) async throws -> Void

    var sourceText = ""
    var destinationText = ""
    var maximumDepth = 5
    var maximumFunctions = 96
    private(set) var phase: Phase = .idle
    private(set) var rows: [NEWFEATURESCallPathRow] = []
    private(set) var summary: Summary?
    private(set) var isBusy = false

    @ObservationIgnored private let currentContext: @MainActor () -> NEWFEATURESCallPathViewContext?
    @ObservationIgnored private let run: Runner
    @ObservationIgnored private let navigate: @MainActor (NEWFEATURESCallPathRow, NEWFEATURESImageKey) throws -> Bool
    @ObservationIgnored private var presentedContext: NEWFEATURESCallPathViewContext?
    @ObservationIgnored private var resultImage: NEWFEATURESImageKey?
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var invocationID: UUID?
    @ObservationIgnored private var acceptsResult = false
    @ObservationIgnored private var cancellationNotice: Notice = .cancelled

    init(
        currentContext: @escaping @MainActor () -> NEWFEATURESCallPathViewContext?,
        run: @escaping Runner,
        navigate: @escaping @MainActor (NEWFEATURESCallPathRow, NEWFEATURESImageKey) throws -> Bool
    ) {
        self.currentContext = currentContext
        self.run = run
        self.navigate = navigate
    }

    convenience init(store: WorkspaceStore, session: WorkspaceDocumentSession) {
        let service = NEWFEATURESCallPathService(store: store, session: session)
        let bridge = NEWFEATURESAdmissionBridge(store: store, session: session)
        self.init(currentContext: { [weak store, weak session] in
            guard let store, let session else { return nil }
            return NEWFEATURESCallPathViewContext.read(store: store, session: session)
        }, run: { request, publish in
            try await service.findPath(
                in: request.context.source.focusedSlot, from: request.source, to: request.destination,
                budget: request.budget, publish: publish
            )
        }, navigate: { [weak store] row, image in
            guard let store else { throw NEWFEATURESAdmissionFailure.documentClosed }
            let slot = ImageSlot(rawValue: image.slot)
            let admission = try bridge.admit(slot: slot)
            guard admission.projection.image == image, store.focusedImageSlot == slot else {
                throw NEWFEATURESAdmissionFailure.staleSource
            }
            // Row UUID and address came from the uniquely owned captured path. The full image
            // identity is still exact, so no new range search or name-based remapping is needed.
            guard store.selectAddress(ImageAddress(slot: slot, address: row.address)) else { return false }
            store.syncSidebarSelection(functionID: row.id)
            return true
        })
    }

    deinit { task?.cancel() }

    /// Only bounded ASCII hexadecimal addresses are accepted; names and implicit image guesses
    /// are deliberately absent from this first UI. Prefix 0x is optional.
    static func parseAddress(_ text: String) -> UInt64? {
        guard text.utf8.count <= 32 else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let digits = trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X")
            ? String(trimmed.dropFirst(2)) : trimmed
        guard !digits.isEmpty, digits.utf8.count <= 16,
              digits.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) })
        else { return nil }
        return UInt64(digits, radix: 16)
    }

    func refresh(_ context: NEWFEATURESCallPathViewContext?) {
        let previous = presentedContext
        presentedContext = context
        if previous?.source != context?.source {
            invalidate(.sourceChanged)
            sourceText = selectedAddress(in: context).map(Self.addressText) ?? ""
            destinationText = ""
        } else if previous?.selection != context?.selection, isBusy {
            cancel(.selectionChanged)
        }
        if context == nil {
            invalidate(.unavailable)
        } else if sourceText.isEmpty, let address = selectedAddress(in: context), !isBusy {
            sourceText = Self.addressText(address)
        }
    }

    func useSelection(asDestination: Bool) {
        guard !isBusy, let address = selectedAddress(in: currentContext()) else { return }
        if asDestination { destinationText = Self.addressText(address) }
        else { sourceText = Self.addressText(address) }
        clearResult()
        phase = .idle
    }

    func start() {
        // Do not replace a still-retiring task, even if cancellation was already requested.
        guard task == nil, !isBusy else { return }
        guard let context = currentContext() else { phase = .refused(.unavailable); return }
        guard let source = Self.parseAddress(sourceText),
              let destination = Self.parseAddress(destinationText) else {
            clearResult()
            phase = .refused(.invalidAddress)
            return
        }
        let budget: NEWFEATURESReadBudget
        do {
            budget = try NEWFEATURESReadBudget(maxFunctions: maximumFunctions, maxDepth: maximumDepth)
        } catch {
            clearResult()
            phase = .refused(.inputLimit)
            return
        }
        clearResult()
        presentedContext = context
        let id = UUID()
        invocationID = id
        acceptsResult = true
        isBusy = true
        phase = .searching
        let request = NEWFEATURESCallPathUIRequest(
            context: context, source: source, destination: destination, budget: budget
        )
        task = Task { [weak self] in
            guard let self else { return }
            var failure: Error?
            do {
                try await run(request) { [weak self] delivery in
                    self?.receive(delivery, request: request, invocationID: id)
                }
            } catch { failure = error }
            retired(id, failure: failure)
        }
    }

    func cancel(_ notice: Notice = .cancelled) {
        guard let task else { return }
        acceptsResult = false
        cancellationNotice = notice
        clearResult()
        phase = .cancelling
        task.cancel()
    }

    func disappear() {
        if isBusy { cancel(.hidden) }
    }

    func select(_ row: NEWFEATURESCallPathRow) {
        guard !isBusy, rows.contains(row), let image = resultImage else { return }
        do {
            guard currentContext()?.source == presentedContext?.source,
                  try navigate(row, image) else {
                invalidate(.sourceChanged)
                return
            }
        } catch { invalidate(.sourceChanged) }
    }

    private func receive(
        _ delivery: NEWFEATURESCallPathDelivery,
        request: NEWFEATURESCallPathUIRequest,
        invocationID id: UUID
    ) {
        guard invocationID == id, acceptsResult, !Task<Never, Never>.isCancelled else { return }
        // Read live selection here as well as in onChange: a UI update may not yet have
        // delivered its observer callback when the async service reaches publication.
        guard let context = currentContext(), context == request.context else {
            cancel(currentContext()?.source == request.context.source ? .selectionChanged : .sourceChanged)
            return
        }
        let result = delivery.result
        guard result.pathFunctionIDs.count == result.report.path.count else {
            cancel(.unavailable)
            return
        }
        rows = zip(result.pathFunctionIDs, result.report.path).map {
            NEWFEATURESCallPathRow(id: $0.0, address: $0.1.address)
        }
        resultImage = result.report.source.image
        summary = Summary(
            status: result.report.status, visitedFunctions: result.report.visitedFunctions,
            visitedEdges: result.report.visitedEdges, unresolvedObservations: result.unresolvedObservationCount,
            examinedUnverifiedEdges: result.report.examinedUnverifiedEdges
        )
        phase = .finished
    }

    private func retired(_ id: UUID, failure: Error?) {
        guard invocationID == id else { return }
        task = nil
        invocationID = nil
        isBusy = false
        if !acceptsResult {
            phase = .refused(cancellationNotice)
        } else if let failure {
            clearResult()
            phase = .refused(Self.notice(for: failure))
        } else if summary == nil {
            phase = .refused(.unavailable)
        }
        acceptsResult = false
    }

    private func invalidate(_ notice: Notice) {
        if isBusy { cancel(notice) }
        else {
            let hadResult = summary != nil || phase != .idle
            clearResult()
            if hadResult { phase = .refused(notice) }
        }
    }

    private func clearResult() {
        rows = []
        summary = nil
        resultImage = nil
    }

    private func selectedAddress(in context: NEWFEATURESCallPathViewContext?) -> UInt64? {
        guard let context, let selection = context.selection,
              selection.slot == context.source.focusedSlot else { return nil }
        return selection.address
    }

    private static func addressText(_ address: UInt64) -> String { "0x" + String(address, radix: 16) }

    private static func notice(for error: Error) -> Notice {
        if error is CancellationError { return .cancelled }
        if let interruption = error as? NEWFEATURESGraphInterruption {
            return interruption == .timedOut ? .timedOut : .cancelled
        }
        if let failure = error as? NEWFEATURESAdmissionFailure {
            switch failure {
            case .analysisRequired: return .analysisRequired
            case .sourceIdentityUnavailable: return .identityUnavailable
            case .staleSource: return .sourceChanged
            case .documentClosed: return .unavailable
            case .ambiguousFunction, .functionNotFound: return .ambiguousFunction
            case .inputLimitExceeded: return .inputLimit
            }
        }
        if let failure = error as? NEWFEATURESCallPathFailure {
            switch failure {
            case .unsupportedArchitecture: return .unsupportedArchitecture
            case .invalidFunctionOwnership, .endpointUnresolved: return .ambiguousFunction
            case .inputLimit: return .inputLimit
            case .outputLimit: return .outputLimit
            }
        }
        return .unavailable
    }
}
