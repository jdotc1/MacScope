import Foundation
import NEWFEATURESCore

struct NEWFEATURESCallPathResult: Encodable, Sendable {
    let report: NEWFEATURESPathReport
    /// Ordered alongside report.path; resolved from exact unique captured function ranges.
    let pathFunctionIDs: [UUID]
    let unresolvedObservationCount: Int
    let unresolvedSamples: [NEWFEATURESUnresolvedCallObservation]
    let unresolvedSamplesTruncated: Bool
    let constructionWork: Int
}

struct NEWFEATURESCallPathDelivery: Sendable {
    let result: NEWFEATURESCallPathResult
    let encoded: Data
}

/// App-private service. External operations must still use their existing permission,
/// schema, revocation and evidence-acceptance surfaces before invoking this service.
@MainActor
final class NEWFEATURESCallPathService {
    private weak var store: WorkspaceStore?
    private let admissionBridge: NEWFEATURESAdmissionBridge

    init(store: WorkspaceStore, session: WorkspaceDocumentSession) {
        self.store = store
        admissionBridge = NEWFEATURESAdmissionBridge(store: store, session: session)
    }

    func findPath(
        in slot: ImageSlot,
        from sourceAddress: UInt64,
        to destinationAddress: UInt64,
        budget: NEWFEATURESReadBudget,
        publish: (NEWFEATURESCallPathDelivery) throws -> Void
    ) async throws {
        // The budget starts before any snapshot capture or graph projection.
        let operation = NEWFEATURESGraphOperation(budget: budget)
        try operation.checkpoint()
        let admission = try admissionBridge.admit(slot: slot)
        guard let store else { throw NEWFEATURESAdmissionFailure.documentClosed }
        let captured = store.snapshot
        try admissionBridge.revalidate(admission)
        let image = admission.projection.image

        let task = Task.detached(priority: .userInitiated) {
            try operation.checkpoint()
            guard let analysis = captured.analysis(in: slot), let binary = captured.binary(in: slot) else {
                throw NEWFEATURESAdmissionFailure.analysisRequired
            }
            // Reuse the focused graph input shape without projecting unrelated presentation
            // overrides, CFG layout or user-authored/cross-image xrefs into call evidence.
            let projection = FocusedGraphProjection(
                imageSlot: slot, ownerBinaryID: binary.id, functions: analysis.functions,
                basicBlocks: [], instructions: analysis.instructions, controlFlowEdges: [],
                xrefs: analysis.xrefs, presentationByAddress: [:]
            )
            let input = try NEWFEATURESVerifiedCallProjection.make(
                projection: projection, image: image, sourceAddress: sourceAddress,
                destinationAddress: destinationAddress, operation: operation
            )
            let report = try NEWFEATURESPathfinder.shortestVerifiedPath(
                from: input.source, to: input.destination, graph: input.graph,
                budget: budget, operation: operation
            )
            var pathFunctionIDs: [UUID] = []
            for function in report.path {
                try operation.checkpoint()
                guard let id = input.functionIDsByStart[function.address] else {
                    throw NEWFEATURESCallPathFailure.invalidFunctionOwnership
                }
                pathFunctionIDs.append(id)
            }
            let result = NEWFEATURESCallPathResult(
                report: report, pathFunctionIDs: pathFunctionIDs,
                unresolvedObservationCount: input.unresolvedObservationCount, unresolvedSamples: input.unresolvedSamples,
                unresolvedSamplesTruncated: input.unresolvedSamples.count < input.unresolvedObservationCount,
                constructionWork: input.constructionWork
            )
            try operation.checkpoint()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let encoded = try encoder.encode(result)
            try operation.checkpoint()
            guard encoded.count <= budget.maxTotalUTF8Bytes else {
                throw NEWFEATURESCallPathFailure.outputLimit
            }
            return NEWFEATURESCallPathDelivery(result: result, encoded: encoded)
        }
        // Cancellation reaches the exact detached computation, and this call awaits its
        // retirement. No replacement coordinator, native worker or late publication exists.
        let delivery = try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
        try Task.checkCancellation()
        try operation.checkpoint()
        // Positive, negative and partial results all retain the original admission. The
        // sink is synchronous so no suspension separates its final source check and delivery.
        try admissionBridge.publish(admission.retaining(delivery), to: publish)
    }
}
