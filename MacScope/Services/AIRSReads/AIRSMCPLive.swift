import Combine
import Foundation

/// The reads' view of one live workspace. Every member is a MainActor accessor so tests can drive the
/// same gates with authored values; `live(_:)` binds them to a real store without mutating it.
@MainActor
struct AIRSReadSource {
    var owner: AnyObject
    var focusedSlot: @MainActor () -> ImageSlot
    var installationID: @MainActor () -> UUID
    var analysisGeneration: @MainActor () -> UUID?
    var imageOwnerID: @MainActor (ImageSlot) -> UUID?
    var unwindKey: @MainActor (ImageSlot, UnwindAuditModel) -> UnwindAuditResultKey?
    var unwindState: @MainActor () -> UnwindAuditResultState
    var swiftKey: @MainActor (ImageSlot) -> SwiftErrorFlowSourceKey?
    var capture: @MainActor (ImageSlot) -> AIRSCapturedInput?
    var subscribe: @MainActor (AIRSReadEntry) -> [AnyCancellable]

    static func live(_ store: WorkspaceStore) -> AIRSReadSource {
        AIRSReadSource(
            owner: store,
            focusedSlot: { [unowned store] in store.focusedImageSlot },
            installationID: { [unowned store] in store.documentInstallationID },
            analysisGeneration: { [unowned store] in store.snapshot.analysisGenerationID },
            imageOwnerID: { [unowned store] in store.snapshot.binary(in: $0)?.id },
            unwindKey: { [unowned store] slot, model in store.unwindAuditKey(in: slot, model: model) },
            unwindState: { [unowned store] in store.unwindAuditCoordinator.state },
            swiftKey: { [unowned store] in store.swiftErrorFlowKey(in: $0) },
            capture: { [unowned store] slot in
                guard let binary = store.snapshot.binary(in: slot), let identity = binary.artifactIdentity,
                      let layout = binary.preferredSegmentLayout,
                      let bytes = store.snapshot.analysis(in: slot)?.imageBytes else { return nil }
                return AIRSCapturedInput(imageID: binary.id, bytes: bytes, sourceURL: URL(fileURLWithPath: binary.path),
                                         identity: identity, layout: layout, integrity: binary.artifactIntegrityState)
            },
            subscribe: { [weak store] entry in
                guard let store else { return [] }
                return [
                    store.$focusedImageSlotStorage.dropFirst().sink { [weak entry] _ in entry?.noteFocusChange() },
                    store.$snapshot.dropFirst().sink { [weak entry] _ in entry?.noteSourceChange() },
                    store.$documentInstallationID.dropFirst().sink { [weak entry] _ in entry?.noteSourceChange() },
                    store.unwindAuditCoordinator.$state.dropFirst().sink { [weak entry] _ in entry?.noteReportStateChange() },
                ]
            })
    }
}

/// Injectable work and limits. Defaults are the production seam; tests substitute controllable runners.
struct AIRSReadRuntime: Sendable {
    var census: @Sendable (AIRSCapturedInput) throws -> AIRSCensus = { try AIRSReadInputCapture.liveCensus($0) }
    var swiftRun: AIRSSwiftReadCoordinator.Run = { AIRSSwiftRunner.live($0, $1) }
    var deadlineMillis = 25_000
    static let live = AIRSReadRuntime()
}

@MainActor
enum AIRSMCPLive {
    static let waitLimitMillis: Int64 = 25_000

    // MARK: Transport entry points

    static func executeInline(command: String, arguments: ScriptValue, surface: NavigatorSurface) throws -> ScriptValue {
        let options = try AIRSMCPReads.parse(command: command, arguments: arguments)
        let source = surface.store.map(AIRSReadSource.live)
        switch gate(options: options, source: source, resolve: surface.resolveImage,
                    registry: .shared, runtime: .live) {
        case .answer(let value): return value
        case .work, .page: return refusal("asyncTransportRequired", retryable: true)
        }
    }

    static func executeAsync(command: String, arguments: ScriptValue, surface: NavigatorSurface) async throws -> ScriptValue {
        let options = try AIRSMCPReads.parse(command: command, arguments: arguments)
        let source = surface.store.map(AIRSReadSource.live)
        return try await serve(options: options, source: source, resolve: surface.resolveImage,
                               registry: .shared, runtime: .live)
    }

    /// The whole read, with injectable source, registry and runtime (the integration seam for tests).
    static func serve(options: AIRSReadOptions, source: AIRSReadSource?, resolve: @MainActor (ScriptValue) -> ImageSlot?,
                      registry: AIRSReadSessionRegistry, runtime: AIRSReadRuntime) async throws -> ScriptValue {
        switch gate(options: options, source: source, resolve: resolve, registry: registry, runtime: runtime,
                    offMain: true) {
        case .answer(let value): return value
        case .page(let report, let offset, let limit, let entry):
            return await servePage(report: report, offset: offset, limit: limit, entry: entry)
        case .work(let admission):
            guard let source else { return refusal("analysisUnavailable", retryable: true) }
            return try await finish(admission, source: source, runtime: runtime)
        }
    }

    // MARK: Admission

    struct Admission {
        enum Kind {
            case unwind(report: UnwindAuditReport, key: UnwindAuditResultKey, publicationID: UUID, input: AIRSCapturedInput?)
            case swift(key: SwiftErrorFlowSourceKey, input: AIRSCapturedInput)
            /// Census already cached: only the projection is left, and it runs off the MainActor.
            case unwindProject(report: UnwindAuditReport, key: UnwindAuditResultKey, publicationID: UUID, census: AIRSCensus)
            case swiftProject(raw: AIRSSwiftRawResult, key: SwiftErrorFlowSourceKey)
        }
        var context: AIRSReadContext
        var slot: ImageSlot
        var limit: Int
        var entry: AIRSReadEntry
        var kind: Kind
    }

    enum Gate {
        case answer(ScriptValue)
        case work(Admission)
        /// A validated page of a retained report; encoding is left to the caller (off the MainActor when async).
        case page(report: AIRSReadReport, offset: Int, limit: Int, entry: AIRSReadEntry)
    }

    static func refusal(_ detail: String, code: MCPRefusalCode = .preconditionFailed, retryable: Bool = false,
                        budget: MCPRefusalBudget? = nil, used: Int64? = nil) -> ScriptValue {
        MCPToolRefusal(code: code, detail: detail, retryable: retryable, budget: budget, used: used).value
    }

    static func gate(options: AIRSReadOptions, source: AIRSReadSource?, resolve: @MainActor (ScriptValue) -> ImageSlot?,
                     registry: AIRSReadSessionRegistry, runtime: AIRSReadRuntime, offMain: Bool = false) -> Gate {
        guard let slot = resolve(options.imageSlot) else {
            return .answer(NavigatorMCPCommands.absent(.object(["imageSlot": options.imageSlot]), "noSuchImage"))
        }
        guard let source else { return .answer(refusal("analysisUnavailable", retryable: true)) }
        guard let entry = registry.entry(owner: source.owner, installationID: source.installationID(),
                                         subscribe: source.subscribe) else {
            return .answer(refusal("registryEntryCapacity", code: .budgetExceeded, retryable: true,
                                   budget: MCPRefusalBudget(unit: .nodes, limit: Int64(AIRSReadSessionRegistry.maximumEntries))))
        }
        guard slot == source.focusedSlot() else { return .answer(refusal("focusMismatch", retryable: true)) }
        guard let ownerID = source.imageOwnerID(slot) else {
            return .answer(NavigatorMCPCommands.absent(.object(["imageSlot": options.imageSlot]), "noSuchImage"))
        }
        let isUnwind = options.command == AIRSMCPReads.unwindCommand
        let modelID = options.model.modelID(for: options.command)
        let generation: UUID
        var unwindKey: UnwindAuditResultKey?
        var swiftKey: SwiftErrorFlowSourceKey?
        if isUnwind {
            guard let model = options.model.unwindModel, let key = source.unwindKey(slot, model) else {
                return .answer(refusal("analysisUnavailable", retryable: true))
            }
            unwindKey = key; generation = key.generation
        } else {
            guard let key = source.swiftKey(slot) else { return .answer(refusal("analysisUnavailable", retryable: true)) }
            swiftKey = key; generation = key.generation
        }
        if let id = source.analysisGeneration() { ScriptingGenerationCapture.current?.record(id) }
        let context = AIRSReadContext(
            command: options.command, model: options.model, modelID: modelID, imageSlot: slot.rawValue,
            imageOwnerID: ownerID, installationID: source.installationID(), generation: generation,
            entryID: entry.id, epochs: entry.epochs, function: options.function)

        if let cursor = options.cursor {
            guard let report = validatedReport(cursor, context: context, entry: entry) else {
                return .answer(NavigatorMCPCommands.staleCursor)
            }
            return pageGate(report, offset: cursor.offset, options: options, context: context, entry: entry, offMain: offMain)
        }

        if let cached = entry.report(command: options.command, modelID: modelID, filterToken: context.filterToken,
                                     slot: slot.rawValue) {
            if cached.generation == generation && cached.imageOwnerID == ownerID
                && cached.reportStateEpoch == context.epochs.reportState {
                return pageGate(cached, offset: 0, options: options, context: context, entry: entry, offMain: offMain)
            }
            entry.discard(id: cached.id)
        }

        if isUnwind, let key = unwindKey {
            let state = source.unwindState()
            guard state.key == key else { return .answer(refusal("auditNotReady", retryable: true)) }
            switch state.phase {
            case .idle, .running: return .answer(refusal("auditNotReady", retryable: true))
            case .cancelled: return .answer(refusal("readCancelled", code: .cancelled, retryable: true))
            case .failed(let message):
                return .answer(AIRSAbort.refusal(
                    MCPToolRefusal(code: .preconditionFailed, detail: "coordinatorFailed", retryable: false),
                    denominators: nil, diagnostic: String(message.prefix(256))))
            case .completed:
                guard let report = state.report, let publicationID = state.publicationID else {
                    return .answer(refusal("auditNotReady", retryable: true))
                }
                if let census = entry.cachedCensus(generation: generation, slot: slot.rawValue) {
                    if offMain {
                        return .work(Admission(context: context, slot: slot, limit: options.limit, entry: entry,
                                               kind: .unwindProject(report: report, key: key, publicationID: publicationID, census: census)))
                    }
                    return .answer(finalize(AIRSReadBuilder.unwind(report: report, census: census, context: context),
                                            options: options, context: context, entry: entry, source: source, slot: slot))
                }
                return .work(Admission(context: context, slot: slot, limit: options.limit, entry: entry,
                                       kind: .unwind(report: report, key: key, publicationID: publicationID, input: source.capture(slot))))
            }
        }

        guard let key = swiftKey else { return .answer(refusal("analysisUnavailable", retryable: true)) }
        if let raw = entry.swift.cachedResult(key: key, model: options.model) {
            if offMain {
                return .work(Admission(context: context, slot: slot, limit: options.limit, entry: entry,
                                       kind: .swiftProject(raw: raw, key: key)))
            }
            return .answer(finalize(AIRSReadBuilder.swift(raw: raw, context: context), options: options,
                                    context: context, entry: entry, source: source, slot: slot))
        }
        guard let input = source.capture(slot) else { return .answer(refusal("analysisUnavailable", retryable: true)) }
        return .work(Admission(context: context, slot: slot, limit: options.limit, entry: entry,
                               kind: .swift(key: key, input: input)))
    }

    // MARK: Heavy part

    private static func finish(_ admission: Admission, source: AIRSReadSource, runtime: AIRSReadRuntime) async throws -> ScriptValue {
        let context = admission.context
        switch admission.kind {
        case .unwind(let report, let key, let publicationID, let input):
            var census: AIRSCensus?
            if let input {
                guard AIRSReadInputCapture.withinBound(input) else {
                    return AIRSAbort.refusal(
                        MCPToolRefusal(code: .budgetExceeded, detail: "retainedInputByteLimit", retryable: false,
                                       budget: MCPRefusalBudget(unit: .bytes, limit: Int64(AIRSReadInputCapture.maximumRetainedBytes)),
                                       used: Int64(input.bytes.count)), denominators: nil)
                }
                let loader = runtime.census
                let outcome = await airsAwait(deadlineMillis: runtime.deadlineMillis) {
                    await AIRSReadCaptureWorker.shared.census(input, loader: loader)
                }
                switch outcome {
                case .failure(.deadline):
                    return AIRSAbort.refusal(deadlineRefusal(runtime), denominators: nil)
                case .failure(.cancelled):
                    return AIRSAbort.refusal(MCPToolRefusal(code: .cancelled, detail: "readCancelled", retryable: true),
                                             denominators: nil)
                case .success(.success(let value)): census = value
                case .success(.failure): census = nil
                }
            }
            let projected = await AIRSReadProjection.detachedUnwind(report: report, census: census, context: context,
                                                                    limit: admission.limit)
            if let stale = revalidate(admission, source: source, unwind: (key, publicationID)) { return stale }
            if let census { admission.entry.retainCensus(census, generation: context.generation, slot: context.imageSlot) }
            return commit(projected, entry: admission.entry)
        case .unwindProject(let report, let key, let publicationID, let census):
            let projected = await AIRSReadProjection.detachedUnwind(report: report, census: census, context: context,
                                                                    limit: admission.limit)
            if let stale = revalidate(admission, source: source, unwind: (key, publicationID)) { return stale }
            return commit(projected, entry: admission.entry)
        case .swiftProject(let raw, _):
            let projected = await AIRSReadProjection.detachedSwift(raw: raw, context: context, limit: admission.limit)
            if let stale = revalidate(admission, source: source, unwind: nil) { return stale }
            return commit(projected, entry: admission.entry)
        case .swift(let key, let input):
            guard AIRSReadInputCapture.withinBound(input) else {
                return AIRSAbort.refusal(
                    MCPToolRefusal(code: .budgetExceeded, detail: "retainedInputByteLimit", retryable: false,
                                   budget: MCPRefusalBudget(unit: .bytes, limit: Int64(AIRSReadInputCapture.maximumRetainedBytes)),
                                   used: Int64(input.bytes.count)), denominators: nil)
            }
            let outcome = await admission.entry.swift.result(
                key: key, model: context.model, input: input, deadlineMillis: runtime.deadlineMillis, run: runtime.swiftRun)
            switch outcome {
            case .failure(.busy):
                return refusal("analysisBusy", code: .budgetExceeded, retryable: true,
                               budget: MCPRefusalBudget(unit: .nodes, limit: 1))
            case .failure(.deadline):
                return AIRSAbort.refusal(deadlineRefusal(runtime), denominators: nil)
            case .failure(.cancelled):
                return AIRSAbort.refusal(MCPToolRefusal(code: .cancelled, detail: "readCancelled", retryable: true), denominators: nil)
            case .failure(.superseded):
                return refusal("staleReport", retryable: true)
            case .success(let raw):
                let projected = await AIRSReadProjection.detachedSwift(raw: raw, context: context, limit: admission.limit)
                if let stale = revalidate(admission, source: source, unwind: nil) { return stale }
                return commit(projected, entry: admission.entry)
            }
        }
    }

    private static func deadlineRefusal(_ runtime: AIRSReadRuntime) -> MCPToolRefusal {
        MCPToolRefusal(code: .budgetExceeded, detail: "readDeadlineExceeded", retryable: true,
                       budget: MCPRefusalBudget(unit: .wallMillis, limit: Int64(runtime.deadlineMillis)))
    }

    /// Re-check, after suspension, that everything the admission captured is still current.
    private static func revalidate(_ admission: Admission, source: AIRSReadSource,
                                   unwind: (UnwindAuditResultKey, UUID)?) -> ScriptValue? {
        let c = admission.context
        guard source.focusedSlot() == admission.slot else { return refusal("focusChanged", retryable: true) }
        guard admission.entry.epochs == c.epochs, source.installationID() == c.installationID,
              source.imageOwnerID(admission.slot) == c.imageOwnerID else { return refusal("staleReport", retryable: true) }
        if let (key, publicationID) = unwind {
            let state = source.unwindState()
            guard state.key == key, state.phase == .completed, state.publicationID == publicationID,
                  source.unwindKey(admission.slot, state.key?.model ?? .boundedLoops) == key else {
                return refusal("staleReport", retryable: true)
            }
        } else if case .swift(let key, _) = admission.kind, source.swiftKey(admission.slot) != key {
            return refusal("staleReport", retryable: true)
        } else if case .swiftProject(_, let key) = admission.kind, source.swiftKey(admission.slot) != key {
            return refusal("staleReport", retryable: true)
        }
        return nil
    }

    // MARK: Report to page

    /// Inline (synchronous) path: projection and encoding stay on the MainActor here by necessity.
    private static func finalize(_ built: AIRSBuildResult, options: AIRSReadOptions, context: AIRSReadContext,
                                 entry: AIRSReadEntry, source: AIRSReadSource, slot: ImageSlot) -> ScriptValue {
        commit(AIRSReadProjection.firstPage(built, limit: options.limit, entryID: entry.id), entry: entry)
    }

    /// Back on the MainActor: retain only a report whose first page was built and carries a cursor.
    private static func commit(_ projected: AIRSReadProjection.Projected, entry: AIRSReadEntry) -> ScriptValue {
        if let report = projected.retain { entry.retain(report) }
        return projected.value
    }

    private static func pageGate(_ report: AIRSReadReport, offset: Int, options: AIRSReadOptions, context: AIRSReadContext,
                                 entry: AIRSReadEntry, offMain: Bool) -> Gate {
        if offMain { return .page(report: report, offset: offset, limit: options.limit, entry: entry) }
        return .answer(page(report: report, offset: offset, limit: options.limit, context: context, entry: entry))
    }

    private static func servePage(report: AIRSReadReport, offset: Int, limit: Int, entry: AIRSReadEntry) async -> ScriptValue {
        let entryID = entry.id
        let value = await Task.detached { AIRSReadProjection.page(report: report, offset: offset, limit: limit, entryID: entryID) }.value
        entry.noteServed(id: report.id, liveCursor: AIRSReadProjection.hasCursor(value))
        return value
    }

    private static func page(report: AIRSReadReport, offset: Int, limit: Int, context: AIRSReadContext,
                             entry: AIRSReadEntry) -> ScriptValue {
        let value = AIRSReadProjection.page(report: report, offset: offset, limit: limit, entryID: entry.id)
        entry.noteServed(id: report.id, liveCursor: AIRSReadProjection.hasCursor(value))
        return value
    }

    /// A continuation never computes: it binds to retained state or is exactly `staleCursor`.
    private static func validatedReport(_ cursor: AIRSReadCursor, context: AIRSReadContext,
                                        entry: AIRSReadEntry) -> AIRSReadReport? {
        guard let report = entry.report(id: cursor.reportID),
              cursor.command == context.command, cursor.entryID == entry.id,
              cursor.imageSlot == context.imageSlot, cursor.imageOwnerID == context.imageOwnerID,
              cursor.installationID == context.installationID, cursor.generation == context.generation,
              cursor.focusEpoch == context.epochs.focus, cursor.reportStateEpoch == context.epochs.reportState,
              cursor.modelID == context.modelID, cursor.filterToken == context.filterToken,
              report.command == cursor.command, report.modelID == cursor.modelID,
              report.filterToken == cursor.filterToken, report.imageSlot == cursor.imageSlot,
              report.imageOwnerID == cursor.imageOwnerID, report.installationID == cursor.installationID,
              report.generation == cursor.generation, report.entryID == cursor.entryID,
              report.focusEpoch == cursor.focusEpoch, report.reportStateEpoch == cursor.reportStateEpoch else {
            return nil
        }
        return report
    }
}

/// Pure, nonisolated projection and page encoding over Sendable values; no store, entry or registry access.
enum AIRSReadProjection {
    struct Projected: Sendable {
        var value: ScriptValue
        /// Non-nil only when the first page was built and issued a cursor (single-page reads take no slot).
        var retain: AIRSReadReport?
    }

    nonisolated static func hasCursor(_ value: ScriptValue) -> Bool { value["nextCursor"]?.stringValue != nil }

    nonisolated static func firstPage(_ built: AIRSBuildResult, limit: Int, entryID: UUID) -> Projected {
        switch built {
        case .absent(let subject, let reason): return Projected(value: NavigatorMCPCommands.absent(subject, reason))
        case .aborted(let value): return Projected(value: value)
        case .report(let report):
            let value = page(report: report, offset: 0, limit: limit, entryID: entryID)
            return Projected(value: value, retain: hasCursor(value) ? report : nil)
        }
    }

    nonisolated static func detachedUnwind(report: UnwindAuditReport, census: AIRSCensus?, context: AIRSReadContext,
                                           limit: Int) async -> Projected {
        await Task.detached {
            firstPage(AIRSReadBuilder.unwind(report: report, census: census, context: context), limit: limit,
                      entryID: context.entryID)
        }.value
    }

    nonisolated static func detachedSwift(raw: AIRSSwiftRawResult, context: AIRSReadContext, limit: Int) async -> Projected {
        await Task.detached {
            firstPage(AIRSReadBuilder.swift(raw: raw, context: context), limit: limit, entryID: context.entryID)
        }.value
    }

    nonisolated static func page(report: AIRSReadReport, offset: Int, limit: Int, entryID: UUID) -> ScriptValue {
        let outcome = AIRSReadPager.page(report: report, offset: offset, limit: limit) { next in
            AIRSReadCursor(command: report.command, entryID: entryID, reportID: report.id, imageSlot: report.imageSlot,
                           imageOwnerID: report.imageOwnerID, installationID: report.installationID,
                           generation: report.generation, focusEpoch: report.focusEpoch,
                           reportStateEpoch: report.reportStateEpoch, modelID: report.modelID,
                           filterToken: report.filterToken, offset: next).encoded()
        }
        switch outcome {
        case .page(let value): return value
        case .refusal(let value): return value.value
        case .offsetOutOfBounds(let total):
            return ToolArgumentError(field: "cursor", code: .outOfBounds,
                detail: "Field 'cursor' is outside the retained report.", minimum: 0, maximum: Int64(total)).refusal.value
        }
    }
}
