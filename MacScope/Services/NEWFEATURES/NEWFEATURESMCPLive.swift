import Foundation
import NEWFEATURESCore

/// Live execution of the `verified-call-path` read: admission against the owning document
/// session, an off-MainActor projection and enumeration, then a revalidation before the answer
/// leaves. Never falls back to the raw `call-path` search.
@MainActor
enum NEWFEATURESMCPLive {
    /// Everything that answers before the heavy part, shared by the inline and async transports:
    /// argument shape, then an unknown imageSlot (typed absence), then the owning document session
    /// (a typed refusal when there is none). Never falls back to the raw `call-path`.
    private enum Gate {
        case answer(ScriptValue)
        case proceed(request: NEWFEATURESMCPReads.CallPathRequest, slot: ImageSlot,
                     store: WorkspaceStore, session: WorkspaceDocumentSession)
    }

    private static func gate(arguments: ScriptValue, store: WorkspaceStore?,
                             resolveImage: (ScriptValue) -> ImageSlot?) throws -> Gate {
        let request = try NEWFEATURESMCPReads.parseCallPath(arguments)
        guard let raw = arguments[WorkspaceScriptingAPI.imageSlotFilterArgument],
              let slot = resolveImage(raw) else {
            return .answer(NavigatorMCPCommands.absent(
                .object([WorkspaceScriptingAPI.imageSlotFilterArgument: arguments[WorkspaceScriptingAPI.imageSlotFilterArgument] ?? .null]),
                "noSuchImage"))
        }
        do {
            guard let store else { throw NEWFEATURESSessionLookupError.documentSessionUnavailable }
            return .proceed(request: request, slot: slot, store: store,
                            session: try NEWFEATURESSessionLookup.session(for: store))
        } catch let error as NEWFEATURESSessionLookupError {
            return .answer(refusal(error))
        }
    }

    /// The navigator refusal shape; the reason text is the error's own description.
    private static func refusal<E: Error>(_ error: E) -> ScriptValue {
        NavigatorMCPCommands.refused(NavigatorRefusal("preconditionFailed", "\(error)"))
    }

    /// Inline transport: answers exactly what the async path answers before its heavy part. The
    /// enumeration itself needs the async transport, so an admitted request is refused here, typed.
    static func verifiedCallPathInline(arguments: ScriptValue, store: WorkspaceStore?,
                                       resolveImage: (ScriptValue) -> ImageSlot?) throws -> ScriptValue {
        switch try gate(arguments: arguments, store: store, resolveImage: resolveImage) {
        case .answer(let value): return value
        case .proceed:
            return NavigatorMCPCommands.refused(NavigatorRefusal(
                "preconditionFailed", "verified-call-path is served by the async transport"))
        }
    }

    static func verifiedCallPath(arguments: ScriptValue, store: WorkspaceStore?,
                                 resolveImage: (ScriptValue) -> ImageSlot?) async throws -> ScriptValue {
        switch try gate(arguments: arguments, store: store, resolveImage: resolveImage) {
        case .answer(let value): return value
        case .proceed(let request, let slot, let store, let session):
            do { return try await run(request: request, slot: slot, store: store, session: session) }
            catch let error as NEWFEATURESAdmissionFailure { return refusal(error) }
        }
    }

    private static func run(request: NEWFEATURESMCPReads.CallPathRequest, slot: ImageSlot,
                            store: WorkspaceStore, session: WorkspaceDocumentSession) async throws -> ScriptValue {
        let bridge = NEWFEATURESAdmissionBridge(store: store, session: session)
        let budget = try NEWFEATURESReadBudget(maxDepth: request.maxDepth)
        let operation = NEWFEATURESGraphOperation(budget: budget)
        try operation.checkpoint()
        let admission = try bridge.admit(slot: slot)
        let captured = store.snapshot
        try bridge.revalidate(admission)
        let image = admission.projection.image

        let task = Task.detached(priority: .userInitiated) { () -> ScriptValue in
            try operation.checkpoint()
            guard let analysis = captured.analysis(in: slot), let binary = captured.binary(in: slot) else {
                throw NEWFEATURESAdmissionFailure.analysisRequired
            }
            let projection = FocusedGraphProjection(
                imageSlot: slot, ownerBinaryID: binary.id, functions: analysis.functions,
                basicBlocks: [], instructions: analysis.instructions, controlFlowEdges: [],
                xrefs: analysis.xrefs, presentationByAddress: [:])
            let input = try NEWFEATURESVerifiedCallProjection.make(
                projection: projection, image: image, sourceAddress: request.source,
                destinationAddress: request.target, operation: operation)
            return try NEWFEATURESMCPReads.callPath(
                request: request, graph: input.graph, source: input.source,
                destination: input.destination, budget: budget, operation: operation)
        }
        let result = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        try Task.checkCancellation()
        try bridge.revalidate(admission)
        return result
    }
}
