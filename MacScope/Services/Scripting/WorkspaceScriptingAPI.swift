import CryptoKit
import Darwin
import Foundation

struct ScriptingCommittedBatchFailure: LocalizedError {
    let command: String
    let count: Int64
    let changed: Int64
    var imageSlot: Int64? = nil
    let reason: String
    var result: ScriptValue? = nil
    var receipt: ScriptingBatchHistoryFailure.Receipt {
        .init(command: command, count: count, changed: changed, imageSlot: imageSlot)
    }
    var errorDescription: String? { "\(receipt.summary); \(reason)" }
}

/// A live mutation may have happened even when its journal append could not be
/// synchronized. Preserve the returned value and state the uncertainty explicitly.
struct ScriptingJournalFailure: LocalizedError {
    let command: String
    let result: ScriptValue
    let reason: String
    let handlerReturned: Bool
    let liveApplied: Bool
    var errorDescription: String? {
        "edit-journal-failed: \(reason); "
            + (liveApplied ? "\(command) changed in-memory overrides; " : "mutation outcome requires inspection; ")
            + "journal durability is unconfirmed. Do not retry automatically; inspect state or explicitly save."
    }
}

struct ScriptingBatchHistoryFailure: LocalizedError {
    struct Receipt: Sendable {
        let command: String
        let count: Int64
        let changed: Int64
        var imageSlot: Int64? = nil
        var summary: String {
            "\(command) returned: count=\(count), changed=\(changed)" + (imageSlot.map { ", imageSlot=\($0)" } ?? "")
        }
        var fields: ScriptValue {
            var values: [String: ScriptValue] = ["count": .int(count), "changed": .int(changed)]
            if let imageSlot { values["imageSlot"] = .int(imageSlot) }
            return .object(values)
        }
    }
    let receipts: [Receipt]
    let omitted: Int
    let reason: String
    var errorDescription: String? {
        let history = receipts.map { "\($0.command): count=\($0.count), changed=\($0.changed)" + ($0.imageSlot.map { ", imageSlot=\($0)" } ?? "") }.joined(separator: "; ")
        return "Earlier batches returned with changes [\(history)]; omitted=\(omitted). Current state may have changed later. " + reason
    }
}

struct ScriptingBatchHistory {
    private(set) var receipts: [ScriptingBatchHistoryFailure.Receipt] = []
    private(set) var omitted = 0
    mutating func record(command: String, count: Int64, changed: Int64, imageSlot: Int64? = nil) {
        guard changed > 0 else { return }
        if receipts.count == 128 { receipts.removeFirst(); omitted += 1 }
        receipts.append(.init(command: command, count: count, changed: changed, imageSlot: imageSlot))
    }
    func failure(_ error: Error) -> Error {
        guard !receipts.isEmpty || omitted > 0 else { return error }
        return ScriptingBatchHistoryFailure(receipts: receipts, omitted: omitted, reason: error.localizedDescription)
    }
}

// Request-local, returned facts; never infer a past slot from current focus.
final class ScriptingBatchReceiptCapture: @unchecked Sendable {
    @TaskLocal static var current: ScriptingBatchReceiptCapture?
    private let lock = NSLock()
    private var value: ScriptingBatchHistoryFailure.Receipt?
    var receipt: ScriptingBatchHistoryFailure.Receipt? { lock.lock(); defer { lock.unlock() }; return value }
    func record(_ receipt: ScriptingBatchHistoryFailure.Receipt) { lock.lock(); value = receipt; lock.unlock() }
}

enum ScriptingError: LocalizedError, Equatable {
    case unknownCommand(String)
    case missingArgument(String)
    case invalidArgument(String)
    /// Optimistic write precondition. This is distinct from cursor staleness.
    case staleEvidence(basedOnGeneration: UUID, currentGeneration: UUID)
    /// A `function` name selector matched more than one function in the command's image
    /// scope — two equal display labels, two equal raw names, or one function's display
    /// label colliding with another function's raw name. `addresses` lists every matching
    /// function start in analysis order so the caller can retry with an `address` selector.
    case ambiguousFunctionSelector(name: String, addresses: [UInt64])
    /// A plain Objective-C method name matched multiple functions, including a category
    /// fallback. Display names and starts list every candidate in analysis order.
    case ambiguousObjCMethodSelector(name: String, candidates: [String], addresses: [UInt64])
    /// An explicit `image` selector (MS-19) named no image loaded in this workspace.
    /// `validSlots` lists every loaded image's slot, ascending.
    case unknownImage(selector: String, validSlots: [Int])
    case structuredRefusal(MCPToolRefusal)

    var errorDescription: String? {
        switch self {
        case .unknownCommand(let name): "Unknown scripting command '\(name)'."
        case .missingArgument(let name): "Missing required argument '\(name)'."
        case .invalidArgument(let detail): "Invalid argument: \(detail)."
        case .staleEvidence(let basedOn, let current):
            "staleEvidence: basedOnGeneration \(basedOn.uuidString), currentGeneration \(current.uuidString). Read fresh evidence before writing."
        case .ambiguousFunctionSelector(let name, let addresses):
            "Ambiguous function selector '\(name)': \(addresses.count) functions match (\(addresses.map { "0x" + String($0, radix: 16) }.joined(separator: ", "))); select by `address` instead."
        case .ambiguousObjCMethodSelector(let name, let candidates, let addresses):
            "Ambiguous Objective-C method '\(name)': \(addresses.count) implementations match (\(zip(candidates, addresses).map { "\($0.0) at 0x" + String($0.1, radix: 16) }.joined(separator: ", "))); select by a category-qualified name or by `address`."
        case .unknownImage(let selector, let validSlots):
            validSlots.isEmpty
                ? "Unknown image '\(selector)': no images are loaded; omit `image` for the primary image."
                : "Unknown image '\(selector)': valid image slots are \(validSlots.map(String.init).joined(separator: ", ")) (pass a slot index or an image-owner ID; omit `image` for the primary image)."
        case .structuredRefusal(let refusal):
            "Invalid argument: " + refusal.detail + (refusal.detail.hasSuffix(".") ? "" : ".")
        }
    }
}

struct ScriptingFunctionAddressResolution {
    let function: FunctionSummary
    let resolution: String
}

/// Shared strict classification; nearest is diagnostic context, never a fallback.
struct ScriptingFunctionAddressSelection {
    let address: UInt64
    private var containing: FunctionSummary?
    private var nearest: FunctionSummary?

    init(address: UInt64) { self.address = address }

    mutating func consider(_ function: FunctionSummary) {
        let contains = function.endAddress > function.startAddress
            ? address >= function.startAddress && address < function.endAddress
            : address == function.startAddress
        if contains, containing == nil { containing = function }
        if function.startAddress <= address,
           nearest.map({ function.startAddress > $0.startAddress }) ?? true {
            nearest = function
        }
    }

    func resolved(snapshot: WorkspaceSnapshot, slot: ImageSlot) throws -> ScriptingFunctionAddressResolution {
        if let function = containing {
            return ScriptingFunctionAddressResolution(function: function,
                resolution: address == function.startAddress ? "exact" : "containing")
        }
        let nearestText = nearest.map {
            "nearest preceding function \($0.name) at 0x\(String($0.startAddress, radix: 16))"
        } ?? "nearest preceding function none"
        let sectionText = snapshot.section(containing: address, in: slot).map {
            "\($0.name) [0x\(String($0.address, radix: 16)), 0x\(String($0.address &+ $0.size, radix: 16)))"
        } ?? "none"
        throw ScriptingError.structuredRefusal(MCPToolRefusal(
            code: .unknownSubject,
            detail: "address 0x\(String(address, radix: 16)) is outside every function in image slot \(slot.rawValue); " +
                nearestText + "; section " + sectionText,
            requestedAddress: address, imageSlot: slot.rawValue,
            nearestFunction: nearest.map {
                MCPRefusalFunction(name: String($0.name.prefix(1_024)), address: $0.startAddress)
            },
            section: snapshot.section(containing: address, in: slot).map {
                MCPRefusalSection(name: $0.name, start: $0.address, end: $0.address &+ $0.size)
            }))
    }
}

/// Describes a built-in scripting command so a binding can introspect the surface
/// (the `commands` command returns these).
struct ScriptingCommandInfo: Equatable, Sendable {
    var name: String
    var summary: String
    var mutates: Bool
    var arguments: [String]

    /// Add the common write precondition without editing every command's own argument parser.
    var withEvidencePrecondition: Self {
        guard mutates, !arguments.contains("basedOnGeneration") else { return self }
        var result = self
        result.arguments.append("basedOnGeneration")
        result.summary += " Optional basedOnGeneration is an analysis-generation UUID from prior evidence; a mismatch refuses the write with staleEvidence and both generations. MCP write replies disclose the resulting generation; guarded object replies also include generation."
        return result
    }
}

/// Request-owned provenance for transport metadata. Detached reads record the UUID of their
/// captured snapshot before leaving MainActor, never the live UUID at response-encoding time.
/// The lock also makes the value safe to read from non-MainActor transport code.
final class ScriptingGenerationCapture: @unchecked Sendable {
    @TaskLocal static var current: ScriptingGenerationCapture?
    private let lock = NSLock()
    private var value: UUID?

    func record(_ generation: UUID) {
        lock.lock(); defer { lock.unlock() }
        value = generation
    }

    var generation: UUID? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    var metadata: ScriptValue {
        .object(generation.map { ["generation": .string($0.uuidString)] } ?? [:])
    }

    /// CLI and AppleScript replies have no MCP content/_meta envelope. Object results gain an
    /// additive `generation` (an existing key is never overwritten); arrays and scalars keep
    /// their legacy shape. The value is the captured snapshot UUID, never a second source.
    func disclosing(_ result: ScriptValue) -> ScriptValue {
        guard let generation, case .object(let fields) = result, fields["generation"] == nil else { return result }
        return WorkspaceScriptingAPI.withGeneration(result, generation: generation)
    }

    /// Standard text content works with the advertised 2024-11-05 MCP version and reaches
    /// the model. Keep the legacy payload first and any existing dispatch-note block second.
    func appendingGeneration(to content: [ScriptValue]) -> [ScriptValue] {
        guard let generation else { return content }
        let text = "{\"generation\":\"\(generation.uuidString)\"}"
        return content + [.object(["type": .string("text"), "text": .string(text)])]
    }
}

/// Read-only commands whose CPU-heavy work runs over an immutable snapshot. The async
/// binding executes them off MainActor with request-owned cooperative cancellation.
enum ScriptingSnapshotRead: String, Sendable, CaseIterable {
    case annotationGaps = "annotation-gaps"
    case decompile
    case parameterBindingAudit = "parameter-binding-audit"
    case basicBlocks = "basic-blocks"
}

/// MainActor state a snapshot read needs, captured once at admission.
struct ScriptingSnapshotReadContext: Sendable {
    let snapshot: WorkspaceSnapshot
    let focusedSlot: ImageSlot
}

/// One scripted/MCP `decompile` request handed to the native (SLEIGH) decompiler: the same
/// app-owned runtime the pseudocode pane and the reconstruction loop drive.
struct ScriptingNativeDecompileRequest: Sendable {
    let snapshot: WorkspaceSnapshot
    let imageSlot: ImageSlot
    let functionID: UUID
    let startAddress: UInt64
}

/// Outcome of one native attempt. Anything other than a completed, non-blank document makes
/// `decompile` fall back to MacIR and report why in `fallbackReason`.
enum ScriptingNativeDecompileOutcome: Equatable, Sendable {
    /// The native runtime answered; a nil or blank document reports `native-empty`.
    case completed(NativeDecompilerWirePseudocodeDocument?)
    /// Native is disabled, shut down, not packaged, or cannot project this image.
    case unavailable
    /// Native ran and failed; `code` is short and machine-readable (`timed-out`, `busy`, ...).
    case failed(code: String)

    /// The pane's terminal classification, reused so scripting and UI agree on "unavailable".
    static func terminal(_ reason: NativeDecompilerPresentationTerminalReason) -> Self {
        if reason.isUnavailable { return .unavailable }
        switch reason {
        case .provider(let code, _): return .failed(code: code.rawValue)
        case .client(let failure): return .failed(code: "client-\(failure.rawValue)")
        case .invalidReply: return .failed(code: "invalid-reply")
        case .transportFailure: return .failed(code: "transport-failure")
        case .projection(let error): return .failed(code: "projection-\(error)")
        case .runtimeValidation(let error): return .failed(code: "runtime-validation-\(error)")
        case .runtime(let error): return .failed(code: "runtime-\(error)")
        }
    }
}

struct ScriptingNativeDecompileDisclosure: Equatable, Sendable {
    let outcome: ScriptingNativeDecompileOutcome
    /// A classified cause and its short diagnostic code when no document answered.
    let cause: String?
    let detail: String?
    /// hit or miss for a completed document; nil when the conformer cannot tell.
    let cache: String?
}

/// Injectable native decompile seam. Production binds the app-owned
/// `NativeDecompilerRuntimeRegistry`; tests inject fixed outcomes without the XPC service.
/// Called from a detached task, never on MainActor.
protocol ScriptingNativeDecompiling: Sendable {
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome
    func decompileDisclosed(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileDisclosure
}

extension ScriptingNativeDecompiling {
    func decompileDisclosed(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileDisclosure {
        let outcome = await decompile(request)
        switch outcome {
        case .completed:
            return .init(outcome: outcome, cause: nil, detail: nil, cache: nil)
        case .unavailable:
            return .init(outcome: outcome, cause: ScriptingNativeFallbackCause.unknown,
                detail: "native-unavailable", cache: nil)
        case .failed(let code):
            let classified = ScriptingNativeFallbackCause.classify(code: code)
            return .init(outcome: outcome, cause: classified.cause, detail: classified.detail, cache: nil)
        }
    }
}

/// `backend` / `fallbackReason` values carried by every `decompile` result.
enum ScriptingDecompileBackend {
    static let native = "native"
    static let macIR = "macir"
    static let nativeUnavailable = "native-unavailable"
    static let nativeEmpty = "native-empty"
    /// E2: native text carries no per-line addresses, so authored comments cannot be placed in it.
    static let userComments = "user-comments"
    static func nativeFailed(_ code: String) -> String { "native-failed: \(code)" }
}

enum ScriptingNativeFallbackCause {
    static let notBound = "notBound"
    static let disabled = "disabled"
    static let notInstalled = "notInstalled"
    static let xpcUnavailable = "xpcUnavailable"
    static let budget = "budget"
    static let error = "error"
    static let unknown = "unknown"
    /// The request asked for something the native backend cannot honor (E4 folds).
    static let notApplicable = "notApplicable"
    /// E2: the function has authored comments, which only the MacIR renderer can place.
    static let userComments = "user-comments"

    static func classify(_ reason: NativeDecompilerPresentationTerminalReason) -> (cause: String, detail: String) {
        let cause: String
        switch reason {
        case .provider(_, let detail?) where detail == "native-provider-output-budget-exceeded":
            cause = budget
        case .projection(.functionExceedsBudget), .projection(.tooManyMemoryRegions),
             .projection(.tooManySymbols), .projection(.requestTooLarge),
             .client(.timedOut), .client(.requestTooLarge), .client(.responseTooLarge),
             .provider(.timedOut, _), .provider(.requestTooLarge, _), .provider(.responseTooLarge, _):
            cause = budget
        // Unavailability does not prove the runtime is absent from disk.
        case .provider(.unavailable, _), .runtime(.runtimeAuthorityUnavailable):
            cause = unknown
        case .client(.connectionUnavailable), .client(.connectionFailure), .client(.interrupted),
             .client(.invalidated), .transportFailure, .runtime(.shutDown):
            cause = xpcUnavailable
        default:
            cause = error
        }
        return (cause, reason.diagnosticCode)
    }

    static func classify(code: String) -> (cause: String, detail: String) {
        if ["native-provider-output-budget-exceeded", "timed-out", "request-too-large", "response-too-large",
            "client-timedOut", "client-requestTooLarge", "client-responseTooLarge",
            "projection-functionExceedsBudget", "projection-tooManyMemoryRegions",
            "projection-tooManySymbols", "projection-requestTooLarge"].contains(code) {
            return (budget, code)
        }
        if ["client-connectionUnavailable", "client-connectionFailure", "client-interrupted",
            "client-invalidated", "transport-failure", "runtime-shutDown"].contains(code) {
            return (xpcUnavailable, code)
        }
        if ["unavailable", "runtime-runtimeAuthorityUnavailable"].contains(code) {
            return (unknown, code)
        }
        return (error, code)
    }
}

enum DecompileBackendChoice: String, Sendable { case native, macir, both }

extension WorkspaceScriptingAPI {
    nonisolated static func decompileBackendChoice(_ arguments: ScriptValue) throws -> DecompileBackendChoice? {
        guard let value = arguments["backend"], value != .null else { return nil }
        guard let name = value.stringValue, let choice = DecompileBackendChoice(rawValue: name) else {
            throw ScriptingError.invalidArgument("backend must be native, macir or both")
        }
        if choice == .both, let cursor = arguments["cursor"], cursor != .null {
            throw ScriptingError.invalidArgument("backend both cannot accompany cursor")
        }
        // E4 Q3: a fold is a MacIR presentation; native and the paired reply cannot honor it.
        let requestedFold = try decompileFold(arguments)
        if choice != .macir, !requestedFold.isEmpty {
            throw ScriptingError.invalidArgument(
                "fold: backend \(choice.rawValue) cannot accompany fold; use backend macir or omit backend")
        }
        return choice
    }

    /// Opt-in presentation folds. Absent, null and an empty array all mean no fold, and the
    /// reply is then byte-identical to a request without the field.
    nonisolated static func decompileFold(_ arguments: ScriptValue) throws -> Set<PseudocodeFoldKind> {
        guard let value = arguments["fold"], value != .null else { return [] }
        guard let items = value.arrayValue else {
            throw ScriptingError.invalidArgument("fold must be an array of strings; supported: arc")
        }
        var kinds: Set<PseudocodeFoldKind> = []
        for item in items {
            guard let name = item.stringValue else {
                throw ScriptingError.invalidArgument("fold must be an array of strings; supported: arc")
            }
            guard let kind = PseudocodeFoldKind(rawValue: name) else {
                throw ScriptingError.invalidArgument("fold: unknown kind '\(name)'; supported: arc")
            }
            kinds.insert(kind)
        }
        return kinds
    }

    nonisolated private static func nativeBackendRefusal(cause: String, detail: String) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
            detail: "native backend did not answer: \(cause) (\(detail))", retryable: false, field: "backend"))
    }

    nonisolated private static func pairedDecompileReply(
        native: ScriptValue, macir: ScriptValue, nativeCommentsNotApplied: Bool = false
    ) -> ScriptValue {
        guard case .object(var nativeFields) = native, case .object(var macirFields) = macir else { return macir }
        if nativeCommentsNotApplied { nativeFields["userCommentsNotApplied"] = .bool(true) }
        var fields: [String: ScriptValue] = ["backend": .string("both")]
        for key in ["function", "address", "demangled", "imageSlot", "imageOwner",
                    "resolvedFunction", "resolution", "requestedAddress"] {
            if let value = macirFields.removeValue(forKey: key) { fields[key] = value }
            nativeFields.removeValue(forKey: key)
        }
        for key in ["fallbackReason", "fallbackCause", "fallbackDetail"] { macirFields.removeValue(forKey: key) }
        nativeFields.removeValue(forKey: "backendRequested")
        fields["native"] = .object(nativeFields)
        fields["macir"] = .object(macirFields)
        return .object(fields)
    }
}

/// The in-process automation surface: named commands that query and mutate the loaded
/// workspace, exchanging JSON (`ScriptValue`). This is the single place where a command
/// identifier maps to a real `WorkspaceStore` operation — every binding (a Python
/// embed, an MCP / JSON-RPC server, a CLI) drives THIS. Mutating commands go through
/// the store's undoable authoring methods, so scripted edits are reversible exactly
/// like manual ones.
@MainActor
struct WorkspaceScriptingAPI {
    let store: WorkspaceStore
    /// Observes each cooperative checkpoint of an async snapshot read immediately before
    /// that checkpoint tests cancellation. Production passes nil; tests use it to hold a
    /// detached read at an exact boundary without wall-clock timing.
    let snapshotReadCheckpoint: (@Sendable () -> Void)?
    /// Test factory: return a fresh, unfinished record per admitted call, or nil. Production passes nil. Must not block, reenter the API, or mutate the captured store.
    let phaseAttempt: (@Sendable () -> NativeDecompilerPhaseRecord?)?
    /// Native-first `decompile` for the async binding (MCP). Nil, and every synchronous
    /// binding, serves MacIR with `fallbackReason: native-unavailable`.
    let nativeDecompiler: (any ScriptingNativeDecompiling)?
    /// Async decompile response budget; the outer MCP request deadline remains independent.
    let decompileDeadlineNanoseconds: UInt64

    init(
        store: WorkspaceStore,
        snapshotReadCheckpoint: (@Sendable () -> Void)? = nil,
        nativeDecompiler: (any ScriptingNativeDecompiling)? = nil,
        decompileDeadlineNanoseconds: UInt64 = WorkspaceScriptingAPI.defaultDecompileDeadlineNanoseconds,
        phaseAttempt: (@Sendable () -> NativeDecompilerPhaseRecord?)? = nil
    ) {
        self.store = store
        self.snapshotReadCheckpoint = snapshotReadCheckpoint
        self.nativeDecompiler = nativeDecompiler
        self.decompileDeadlineNanoseconds = decompileDeadlineNanoseconds
        self.phaseAttempt = phaseAttempt
    }

    /// Runs a single command by identifier with JSON arguments, returning a JSON result.
    /// `forcesSynchronousReanalysis: false` (MCP attached to a GUI window) leaves a mutation's
    /// re-flow on the store's normal off-main path, so an agent edit never blocks the UI on analysis.
    func execute(
        _ command: String,
        arguments: ScriptValue = .object([:]),
        proposingPrincipal: Phase2Principal = .human,
        forcesSynchronousReanalysis: Bool = true,
        validateDirectHex: Bool = true
    ) throws -> ScriptValue {
        guard let handler = Self.registry[command] else { throw ScriptingError.unknownCommand(command) }
        // No suspension separates this check from the mutating handler. In particular, it
        // precedes the execution fence and undo/journal work, so a refusal is not a commit.
        if handler.info.mutates {
            try Self.requireCurrentGeneration(arguments, current: store.snapshot.analysisGenerationID)
        }
        let guardedWrite = handler.info.mutates && arguments["basedOnGeneration"] != nil
            && arguments["basedOnGeneration"] != .null
        let arguments = handler.info.mutates ? Self.withoutEvidencePrecondition(arguments) : arguments
        if command != "function-facts" {
            ScriptingGenerationCapture.current?.record(store.snapshot.analysisGenerationID)
        }
        if command == "info" { try Self.validateDirectInfoWait(arguments) }
        if command == "read-evidence" {
            return try Self.readEvidence(arguments, store: store, proposingPrincipal: proposingPrincipal)
        }
        if command == "search" {
            return try Self.searchSynchronously(arguments, store: store, validateDirectHex: validateDirectHex)
        }
        // A mutating command may re-drive analysis (mark-as-data/procedure, patch, …). The store
        // re-flows that OFF the main actor for the interactive UI, but a script is synchronous and
        // expects mutate-then-query to be deterministic — so force the re-flow to complete inline
        // for the span of this command. Read-only commands skip the wrapper (no re-flow to force).
        let checksJournal = handler.info.mutates && !Self.editJournalExemptCommands.contains(command)
        if checksJournal { try store.checkEditJournalFailure() }
        let journal = checksJournal ? store.editJournal : nil
        let priorSequence = journal?.sequence
        let witness = JournalMutationWitness(writer: journal)
        let capture = ScriptingBatchReceiptCapture()
        let rawResult: ScriptValue
        do {
            if handler.info.mutates {
                rawResult = try JournalMutationWitness.$current.withValue(witness) {
                    try ScriptingBatchReceiptCapture.$current.withValue(capture) {
                        try MCPExecutionFence.commit {
                            if forcesSynchronousReanalysis {
                                return try store.withSynchronousReanalysis { try handler.run(arguments, store) }
                            }
                            return try handler.run(arguments, store)
                        }
                    }
                }
            } else if command == "function-facts" {
                let snapshot = store.snapshot
                ScriptingGenerationCapture.current?.record(snapshot.analysisGenerationID)
                rawResult = try Self.snapshotListRead(command, arguments: arguments, snapshot: snapshot,
                    checkpoint: { self.snapshotReadCheckpoint?(); try Task.checkCancellation() })
            } else { rawResult = try handler.run(arguments, store) }
            if !handler.info.mutates {
                recordReadWitness(command: command, arguments: arguments, result: rawResult, snapshot: store.snapshot)
            }
        } catch var failure as ScriptingWriteReadbackFailure {
            // Failed verification is not a committed batch. Keep journal truth
            // and the existing receipt format, without publishing batch receipts.
            if let journal, let priorSequence,
               journal.sequence > priorSequence || journal.failure != nil {
                failure.reply = journalReceipt(failure.reply, writer: journal, from: priorSequence,
                    failed: journal.failure != nil, liveApplied: witness.didApply)
                if journal.failure != nil, case .object(var fields) = failure.reply {
                    fields["recovery"] = .string("Inspect the workspace and explicitly save before further writes. Journal durability is unconfirmed, including the inverse append; do not retry automatically.")
                    failure.reply = .object(fields)
                }
            }
            throw failure
        } catch {
            if let journal, let priorSequence, let failure = journal.failure {
                if let receipt = capture.receipt {
                    ScriptingBatchReceiptCapture.current?.record(receipt)
                    MCPExecutionFence.outcome?.recordBatchReceipt(receipt)
                }
                let partial = journalReceipt(.object(["handlerReturned": .bool(false)]), writer: journal,
                    from: priorSequence, failed: true, liveApplied: witness.didApply)
                throw ScriptingJournalFailure(command: command, result: partial,
                    reason: failure + "; handler error: " + error.localizedDescription,
                    handlerReturned: false, liveApplied: witness.didApply)
            }
            throw error
        }
        let result = guardedWrite
            ? Self.withGeneration(rawResult, generation: store.snapshot.analysisGenerationID) : rawResult
        if handler.info.mutates { ScriptingGenerationCapture.current?.record(store.snapshot.analysisGenerationID) }
        if let receipt = capture.receipt {
            ScriptingBatchReceiptCapture.current?.record(receipt)
            MCPExecutionFence.outcome?.recordBatchReceipt(receipt)
        }
        if checksJournal {
            do { try store.checkEditJournalFailure() }
            catch {
                let reported = journal.flatMap { writer in
                    priorSequence.map { journalReceipt(result, writer: writer, from: $0,
                                                        failed: true, liveApplied: witness.didApply) }
                } ?? result
                let failure = ScriptingJournalFailure(command: command, result: reported,
                    reason: journal?.failure ?? error.localizedDescription,
                    handlerReturned: true, liveApplied: witness.didApply)
                if MCPBatchReceiptBudget.commands.contains(command), let count = result["count"]?.intValue,
                   let changed = result["changed"]?.intValue {
                    throw ScriptingCommittedBatchFailure(command: command, count: count, changed: changed,
                        imageSlot: capture.receipt?.imageSlot ?? result["imageSlot"]?.intValue,
                        reason: failure.localizedDescription, result: reported)
                }
                throw failure
            }
        }
        if let journal, let priorSequence, journal.sequence > priorSequence {
            return journalReceipt(result, writer: journal, from: priorSequence, failed: false, liveApplied: witness.didApply)
        }
        return result
    }

    private func journalReceipt(_ result: ScriptValue, writer: EditJournalWriter, from prior: UInt64,
                                failed: Bool, liveApplied: Bool) -> ScriptValue {
        let count = writer.sequence >= prior ? writer.sequence - prior : 0
        var fields: [String: ScriptValue] = ["scope": .string("v1-address-overrides"),
            "durability": .string(failed ? "unconfirmed" : "synchronized"),
            "synchronizedRecords": .int(Int64(clamping: count))]
        if count > 0 {
            fields["firstSynchronizedSequence"] = .string(String(prior + 1))
            fields["lastSynchronizedSequence"] = .string(String(writer.sequence))
        }
        if failed { fields["liveApplied"] = liveApplied ? .bool(true) : .null; fields["retrySafe"] = .bool(false) }
        if case .object(var output) = result, output["editJournal"] == nil {
            output["editJournal"] = .object(fields); return .object(output)
        }
        return .object(["returnedResult": result, "editJournal": .object(fields)])
    }

    static let editJournalExemptCommands: Set<String> = ["save-workspace", "open-workspace", "goto", "open-claim", "record-callee-outcome", "claim-status"]

    nonisolated static func requireCurrentGeneration(_ arguments: ScriptValue, current: UUID) throws {
        guard let basedOn = try basedOnGeneration(arguments) else { return }
        guard basedOn == current else {
            throw ScriptingError.staleEvidence(basedOnGeneration: basedOn, currentGeneration: current)
        }
    }

    nonisolated static func basedOnGeneration(_ arguments: ScriptValue) throws -> UUID? {
        guard let value = arguments["basedOnGeneration"], value != .null else { return nil }
        guard let text = value.stringValue, let basedOn = UUID(uuidString: text) else {
            throw ScriptingError.invalidArgument("basedOnGeneration must be an analysis-generation UUID string")
        }
        return basedOn
    }

    nonisolated static func withoutEvidencePrecondition(_ arguments: ScriptValue) -> ScriptValue {
        guard case .object(var fields) = arguments else { return arguments }
        fields.removeValue(forKey: "basedOnGeneration")
        return .object(fields)
    }

    /// Object writes gain an additive field; legacy arrays/scalars stay in their old shape.
    /// MCP appends a generation text block, including for empty arrays and scalars.
    nonisolated static func withGeneration(_ result: ScriptValue, generation: UUID) -> ScriptValue {
        guard case .object(var fields) = result else { return result }
        fields["generation"] = .string(generation.uuidString)
        return .object(fields)
    }

    nonisolated static func staleEvidenceReply(basedOn: UUID, current: UUID) -> ScriptValue {
        .object(["error": .string("staleEvidence"),
                 "basedOnGeneration": .string(basedOn.uuidString),
                 "currentGeneration": .string(current.uuidString)])
    }

    nonisolated static func validateDirectInfoWait(_ arguments: ScriptValue) throws {
        guard let value = arguments["waitForReadyMs"] else { return }
        let milliseconds: Int64?
        switch value {
        case .int(let number): milliseconds = number
        case .double(let number): milliseconds = Int64(exactly: number)
        default: milliseconds = nil
        }
        guard let milliseconds, (0...25_000).contains(milliseconds) else {
            throw ScriptingError.invalidArgument("waitForReadyMs must be an exact integer from 0 through 25000")
        }
    }

    nonisolated static func readBytesCount(_ arguments: ScriptValue) throws -> Int {
        guard let value = arguments["count"], value != .null else { return 16 }
        let exact: Int64?
        switch value {
        case .int(let count): exact = count
        case .double(let count): exact = Int64(exactly: count)
        default: exact = nil
        }
        guard let count = exact else {
            throw ScriptingError.invalidArgument("count must be an exact integer in the Int64 range")
        }
        return Int(max(0, count))
    }

    private static func manualXRefKind(_ arguments: ScriptValue) throws -> String {
        guard let value = arguments["kind"], value != .null else { return XRefKind.call }
        guard let kind = value.stringValue else {
            throw ScriptingError.invalidArgument("kind must be a string or null")
        }
        return kind
    }

    static func editJournalHealthValue(_ store: WorkspaceStore) -> ScriptValue {
        .object([
            "state": .string((store.editJournal?.observedHealth ?? .disabled).rawValue),
            "durability": .string("unverified"),
        ])
    }

    nonisolated static func withEditJournalHealth(_ output: ScriptValue, health: ScriptValue?) -> ScriptValue {
        guard let health, case .object(var fields) = output else { return output }
        fields["editJournal"] = health
        return .object(fields)
    }

    static func registerBatchEntries(_ arguments: ScriptValue, clearing: Bool) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"] else {
            throw ScriptingError.invalidArgument("arguments: expected entries only")
        }
        guard let entries = fields["entries"]?.arrayValue, !entries.isEmpty else {
            throw ScriptingError.invalidArgument("entries[0]: at least one entry is required")
        }
        guard entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries[1024]: at most 1024 entries are allowed")
        }
        let allowed: Set<String> = clearing ? ["function", "address", "register"] : ["function", "address", "register", "name"]
        for (index, entry) in entries.enumerated() {
            guard case .object(let values) = entry, Set(values.keys).isSubset(of: allowed) else {
                throw ScriptingError.invalidArgument("entries[\(index)]: unexpected entry fields")
            }
            guard let register = values["register"]?.stringValue,
                  !register.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ScriptingError.invalidArgument("entries[\(index)].register: expected a non-empty string")
            }
            if !clearing && values["name"]?.stringValue == nil {
                throw ScriptingError.invalidArgument("entries[\(index)].name: expected a string")
            }
        }
        return entries
    }

    static func manualXRefBatchEntries(_ arguments: ScriptValue) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"] else {
            throw ScriptingError.invalidArgument("arguments: expected entries only")
        }
        guard let entries = fields["entries"]?.arrayValue, !entries.isEmpty else {
            throw ScriptingError.invalidArgument("entries[0]: at least one entry is required")
        }
        guard entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries[1024]: at most 1024 entries are allowed")
        }
        for (index, entry) in entries.enumerated() {
            guard case .object(let fields) = entry, Set(fields.keys).isSubset(of: ["from", "to", "kind"]) else {
                throw ScriptingError.invalidArgument("entries[\(index)]: unexpected entry fields")
            }
            for endpoint in ["from", "to"] {
                guard fields[endpoint]?.addressValue != nil else {
                    throw ScriptingError.invalidArgument("entries[\(index)].\(endpoint): expected an address")
                }
            }
            if let kind = fields["kind"], kind != .null, kind.stringValue == nil {
                throw ScriptingError.invalidArgument("entries[\(index)].kind: expected a string or null")
            }
        }
        return entries
    }

    static func bookmarkBatchEntries(_ arguments: ScriptValue, removing: Bool) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"] else {
            throw ScriptingError.invalidArgument("arguments: expected entries only")
        }
        guard let entries = fields["entries"]?.arrayValue, !entries.isEmpty else {
            throw ScriptingError.invalidArgument("entries[0]: at least one entry is required")
        }
        guard entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries[1024]: at most 1024 entries are allowed")
        }
        let allowed: Set<String> = removing ? ["address"] : ["address", "name"]
        for (index, entry) in entries.enumerated() {
            guard case .object(let fields) = entry, Set(fields.keys).isSubset(of: allowed) else {
                throw ScriptingError.invalidArgument("entries[\(index)]: unexpected entry fields")
            }
            guard fields["address"]?.addressValue != nil else {
                throw ScriptingError.invalidArgument("entries[\(index)].address: expected an address")
            }
            if !removing, let name = fields["name"], name != .null, name.stringValue == nil {
                throw ScriptingError.invalidArgument("entries[\(index)].name: expected a string")
            }
        }
        return entries
    }

    static func stackLocalBatchEntries(_ arguments: ScriptValue) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"] else {
            throw ScriptingError.invalidArgument("arguments: expected entries only")
        }
        guard let entries = fields["entries"]?.arrayValue, !entries.isEmpty else {
            throw ScriptingError.invalidArgument("entries[0]: at least one entry is required")
        }
        guard entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries[1024]: at most 1024 entries are allowed")
        }
        let allowed: Set<String> = ["function", "address", "local", "name", "type"]
        for (index, entry) in entries.enumerated() {
            guard case .object(let values) = entry, Set(values.keys).isSubset(of: allowed) else {
                throw ScriptingError.invalidArgument("entries[\(index)]: unexpected entry fields")
            }
        }
        return entries
    }

    static func alignmentBatchEntries(_ arguments: ScriptValue) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
        }
        var seen = Set<UInt64>()
        for (index, entry) in entries.enumerated() {
            guard case .object(let row) = entry, Set(row.keys) == ["address", "boundary"], let address = row["address"]?.addressValue,
                  case let .int(boundary)? = row["boundary"], boundary > 1, boundary <= Int64(DataShapeOverride.maxAlignment), boundary & (boundary - 1) == 0 else {
                throw ScriptingError.invalidArgument("entries[\(index)]: expected address and power-of-two boundary")
            }
            guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
        }
        return entries
    }

    static func mergedSignature(_ arguments: ScriptValue, existing: FunctionSignatureOverride?) throws -> FunctionSignatureOverride {
        let returnType: String?
        switch arguments["returnType"] {
        case .none:
            returnType = existing?.returnType
        case .some(.null):
            returnType = nil
        case let .some(.string(value)):
            returnType = value
        case .some:
            throw ScriptingError.invalidArgument("returnType must be a string or null")
        }

        let noReturnState: FunctionSignatureOverride.NoReturnState
        switch (arguments["noReturnState"], arguments["isNoReturn"]) {
        case (.some, .some):
            throw ScriptingError.invalidArgument("provide either noReturnState or isNoReturn, not both")
        case let (.some(.string(value)), .none):
            guard let parsed = FunctionSignatureOverride.NoReturnState(rawValue: value) else {
                throw ScriptingError.invalidArgument(
                    "noReturnState must be one of unspecified|returns|noReturn"
                )
            }
            noReturnState = parsed
        case (.some, .none):
            throw ScriptingError.invalidArgument(
                "noReturnState must be one of unspecified|returns|noReturn"
            )
        case let (.none, .some(.bool(value))):
            noReturnState = value ? .noReturn : .returns
        case (.none, .some):
            throw ScriptingError.invalidArgument("isNoReturn must be a boolean")
        case (.none, .none):
            noReturnState = existing?.noReturnState ?? .unspecified
        }

        let variadicState: FunctionSignatureOverride.VariadicState
        switch arguments["variadicState"] {
        case .none:
            variadicState = existing?.variadicState ?? .unspecified
        case let .some(.string(value)):
            guard let parsed = FunctionSignatureOverride.VariadicState(rawValue: value) else {
                throw ScriptingError.invalidArgument("variadicState must be one of unspecified|fixed|variadic")
            }
            variadicState = parsed
        case .some:
            throw ScriptingError.invalidArgument("variadicState must be one of unspecified|fixed|variadic")
        }

        let parameterList: FunctionSignatureOverride.ParameterListState
        let quarantinedLegacyArgs: [LegacyArgOverride]
        switch arguments["args"] {
        case .none:
            parameterList = existing?.parameterList ?? .unspecified
            quarantinedLegacyArgs = existing?.quarantinedLegacyArgs ?? []
        case .some(.null):
            parameterList = .unspecified
            quarantinedLegacyArgs = []
        case let .some(.array(values)):
            var rowTokens = Set<String>()
            let rows = try values.enumerated().map { index, value -> ArgOverride in
                guard case let .object(fields) = value else {
                    throw ScriptingError.invalidArgument("args[\(index)] must be an object")
                }
                guard case let .some(.string(type)) = fields["type"],
                      !type.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ScriptingError.invalidArgument("args[\(index)].type must be a non-empty string")
                }
                guard Self.isValidSignatureParameterType(type) else {
                    throw ScriptingError.invalidArgument(
                        "args[\(index)].type must be a valid parameter type declaration"
                    )
                }
                let name: String
                switch fields["name"] {
                case .none:
                    name = "arg\(index)"
                case let .some(.string(value)):
                    name = value
                case .some:
                    throw ScriptingError.invalidArgument("args[\(index)].name must be a string")
                }
                var rowToken: String
                repeat {
                    rowToken = UUID().uuidString.lowercased()
                } while !rowTokens.insert(rowToken).inserted
                return ArgOverride(rowToken: rowToken, name: name, type: type, provenance: .script)
            }
            parameterList = .authoritative(rows)
            // A present args value is an intentional active-list replacement;
            // stale ambiguous legacy rows no longer describe the authored list.
            quarantinedLegacyArgs = []
        case .some:
            throw ScriptingError.invalidArgument("args must be an array or null")
        }

        // Return the fully parsed signature before the caller performs any mutation.
        return FunctionSignatureOverride(
            returnType: returnType,
            parameterList: parameterList,
            variadicState: variadicState,
            quarantinedLegacyArgs: quarantinedLegacyArgs,
            noReturnState: noReturnState
        )
    }

    static func segmentEditBatchEntries(_ arguments: ScriptValue, rebasing: Bool) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"],
              let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
        }
        var seen = Set<String>()
        for (index, entry) in entries.enumerated() {
            let allowed: Set<String> = rebasing ? ["section", "delta"] : ["section", "name"]
            guard case .object(let row) = entry, Set(row.keys).isSubset(of: allowed), let section = row["section"]?.stringValue else {
                throw ScriptingError.invalidArgument("entries[\(index)]: expected section and edit fields only")
            }
            guard seen.insert(section).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].section: duplicate section") }
            if rebasing {
                guard let delta = row["delta"], signedDelta(delta) != nil else { throw ScriptingError.invalidArgument("entries[\(index)].delta: expected a signed integer or hex string") }
            } else if let name = row["name"], name != .null, name.stringValue == nil {
                throw ScriptingError.invalidArgument("entries[\(index)].name: expected a string")
            }
        }
        return entries
    }

    static func undefinedBatchEntries(_ arguments: ScriptValue) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
        }
        var seen = Set<UInt64>()
        for (index, entry) in entries.enumerated() {
            guard case .object(let row) = entry, Set(row.keys).isSubset(of: ["address", "isUndefined"]), let address = row["address"]?.addressValue else {
                throw ScriptingError.invalidArgument("entries[\(index)]: expected address and optional isUndefined only")
            }
            guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
            if let value = row["isUndefined"], value.boolValue == nil { throw ScriptingError.invalidArgument("entries[\(index)].isUndefined: expected boolean") }
        }
        return entries
    }

    static func arrayShapeBatchEntries(_ arguments: ScriptValue) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
        }
        var seen = Set<UInt64>()
        for (index, entry) in entries.enumerated() {
            guard case .object(let row) = entry, Set(row.keys).isSubset(of: ["address", "count", "elementType", "format"]), let address = row["address"]?.addressValue,
                  case let .int(count)? = row["count"], count > 0, count <= Int64(DataShapeOverride.maxElementCount) else {
                throw ScriptingError.invalidArgument("entries[\(index)]: expected address and positive integer count")
            }
            guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
            if let type = row["elementType"], type.stringValue == nil { throw ScriptingError.invalidArgument("entries[\(index)].elementType: expected string") }
            if let format = row["format"] {
                guard let value = format.stringValue, value.isEmpty || OperandFormat(rawValue: value) != nil else {
                    throw ScriptingError.invalidArgument("entries[\(index)].format: invalid operand format")
                }
            }
        }
        return entries
    }

    static func stringShapeBatchEntries(_ arguments: ScriptValue) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
        }
        var seen = Set<UInt64>()
        for (index, entry) in entries.enumerated() {
            guard case .object(let row) = entry, Set(row.keys).isSubset(of: ["address", "length"]), let address = row["address"]?.addressValue else {
                throw ScriptingError.invalidArgument("entries[\(index)]: expected address and optional length only")
            }
            guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
            if let length = row["length"] {
                guard case let .int(n) = length, n > 0, n <= Int64(DataShapeOverride.maxStringLength) else {
                    throw ScriptingError.invalidArgument("entries[\(index)].length: expected a positive integer within the string limit")
                }
            }
        }
        return entries
    }

    static func dataProcedureBatchEntries(_ arguments: ScriptValue, procedures: Bool) throws -> [ScriptValue] {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"], let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
        }
        let field = procedures ? "isProcedure" : "isData"
        var seen = Set<UInt64>()
        for (index, entry) in entries.enumerated() {
            guard case .object(let row) = entry, Set(row.keys).isSubset(of: ["address", field]), let address = row["address"]?.addressValue else {
                throw ScriptingError.invalidArgument("entries[\(index)]: expected address and optional \(field) only")
            }
            guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
            if let value = row[field], value.boolValue == nil { throw ScriptingError.invalidArgument("entries[\(index)].\(field): expected boolean") }
        }
        return entries
    }

    static func clearSegmentOverrideEntries(_ arguments: ScriptValue) throws -> [String] {
        guard let entries = arguments["entries"]?.arrayValue, !entries.isEmpty else {
            throw ScriptingError.invalidArgument("entries[0]: at least one entry is required")
        }
        guard entries.count <= 1024 else {
            throw ScriptingError.invalidArgument("entries[1024]: at most 1024 entries are allowed")
        }
        var seen = Set<String>()
        var names: [String] = []
        for (index, item) in entries.enumerated() {
            guard case .object(let fields) = item, Set(fields.keys) == ["section"],
                  let name = fields["section"]?.stringValue else {
                throw ScriptingError.invalidArgument("entries[\(index)].section: expected a section string only")
            }
            guard seen.insert(name).inserted else {
                throw ScriptingError.invalidArgument("entries[\(index)].section: duplicate original section name")
            }
            names.append(name)
        }
        return names
    }

    /// Async bindings keep bounded search off MainActor. The detached scan owns an immutable
    /// snapshot; its cancellation follows this request and no partial result mutates the store.
    /// The CPU-heavy snapshot reads (`annotation-gaps`, `decompile`, `parameter-binding-audit`, `basic-blocks`)
    /// follow the same ownership model and observe cancellation at their phase/loop
    /// boundaries. Other commands retain the existing synchronous authority and mutation
    /// semantics.
    func executeAsync(
        _ command: String,
        arguments: ScriptValue = .object([:]),
        proposingPrincipal: Phase2Principal = .human
    ) async throws -> ScriptValue {
        try await executeAsyncAnnotated(command, arguments: arguments,
            proposingPrincipal: proposingPrincipal, collectDispatchNote: false).result
    }

    func executeAsyncAnnotated(
        _ command: String,
        arguments: ScriptValue = .object([:]),
        proposingPrincipal: Phase2Principal = .human,
        collectDispatchNote: Bool = true,
        validateDirectHex: Bool = true
    ) async throws -> ScriptingAnnotatedResult {
        MCPFatalSignalReporter.prepareAlternateStack()
        if command == "info" {
            try Task.checkCancellation()
            try Self.validateDirectInfoWait(arguments)
        }
        // The async reads never reach the registry closures, so the witness is taken here, against the
        // snapshot (and generation) the read was admitted on, not whatever the store holds after the await.
        let admitted = CalleeReadWitnessLog.witnessingCommands.contains(command) ? store.snapshot : nil
        if Self.snapshotListCommands.contains(command) {
            let annotated = try await executeSnapshotListReadAnnotated(command, arguments: arguments,
                                                                       collectDispatchNote: collectDispatchNote)
            MCPFatalSignalReporter.prepareAlternateStack()
            if let admitted {
                recordReadWitness(command: command, arguments: arguments, result: annotated.result, snapshot: admitted)
            }
            return annotated
        }
        let annotated = ScriptingAnnotatedResult(result: try await executeAsyncUnannotated(
            command, arguments: arguments, proposingPrincipal: proposingPrincipal,
            validateDirectHex: validateDirectHex))
        MCPFatalSignalReporter.prepareAlternateStack()
        if let admitted {
            recordReadWitness(command: command, arguments: arguments, result: annotated.result, snapshot: admitted)
        }
        return annotated
    }

    private func executeAsyncUnannotated(
        _ command: String,
        arguments: ScriptValue = .object([:]),
        proposingPrincipal: Phase2Principal = .human,
        validateDirectHex: Bool = true
    ) async throws -> ScriptValue {
        MCPFatalSignalReporter.prepareAlternateStack()
        if Self.snapshotListCommands.contains(command) {
            return try await executeSnapshotListRead(command, arguments: arguments)
        }
        if command == Self.verifiedCheckpointIsolatedCommand { return try await verifiedCheckpointIsolatedReply(arguments) }
        guard command == "search" else {
            if let read = ScriptingSnapshotRead(rawValue: command) {
                return try await executeSnapshotRead(read, arguments: arguments)
            }
            // Pre-commit boundary. Everything from this check through the handler's return
            // is synchronous on MainActor with no suspension point, so a cancellation that
            // precedes it leaves no effect, and one that arrives later cannot interrupt the
            // commit: the transport then reports the committed receipt, never "cancelled".
            try Task.checkCancellation()
            return try execute(command, arguments: arguments, proposingPrincipal: proposingPrincipal)
        }
        try Task.checkCancellation()
        let query = try Self.string(arguments, "query")
        // The bounded engine admits 256 UTF-8 bytes. The headless and attached authorities refuse
        // a longer query with the typed `invalidPattern(tooLong)` before this point
        // (`HeadlessAutomationAuthority.searchRefusal`); a direct caller still gets this error
        // rather than the engine's empty invalid-query result presented as an exact search.
        guard query.trimmingCharacters(in: .whitespacesAndNewlines).utf8.count <= 256 else {
            throw ScriptingError.invalidArgument("bounded search query exceeds 256 UTF-8 bytes")
        }
        let mode = try Self.searchMode(arguments)
        let snapshot = store.snapshot
        ScriptingGenerationCapture.current?.record(snapshot.analysisGenerationID)
        var scope = Self.searchScope(
            filter: try Self.resolveImageSlotFilter(arguments, snapshot: snapshot),
            focusedSlot: store.focusedImageSlot)
        if let kind = try Self.searchKind(arguments, mode: mode) { scope.kinds = [kind] }
        let slotFilter = try Self.resolveImageSlotFilter(arguments, snapshot: snapshot)
        let decodedCursor: (point: BinarySearchService.SearchResumePoint, cumulative: Int)?
        if let value = arguments["cursor"], value != .null {
            decodedCursor = try Self.decodeSearchCursor(value, query: query, mode: mode,
                kinds: scope.kinds, slotFilter: slotFilter, snapshot: snapshot)
        } else { decodedCursor = nil }
        let capturedScope = scope
        let scan = Task.detached(priority: Task.currentPriority) {
            try Task.checkCancellation()
            if mode == .regex, let detail = BinarySearchService().validate(query: query, mode: mode) {
                try Task.checkCancellation()
                throw ScriptingError.invalidArgument(detail)
            }
            if validateDirectHex, mode == .hex,
               let detail = BinarySearchService().validate(query: query, mode: mode) {
                try Task.checkCancellation()
                throw ScriptingError.invalidArgument(detail)
            }
            let outcome = BinarySearchService().searchBounded(
                query: query, mode: mode, in: snapshot, scope: capturedScope,
                isCancelled: { Task.isCancelled }, resume: decodedCursor?.point
            )
            guard !outcome.isCancelled else { throw CancellationError() }
            try Task.checkCancellation()
            return outcome
        }
        let outcome = try await withTaskCancellationHandler {
            try await scan.value
        } onCancel: {
            scan.cancel()
        }
        try Task.checkCancellation()
        return Self.searchPageReply(outcome, cumulative: decodedCursor?.cumulative ?? 0,
            query: query, mode: mode, kinds: capturedScope.kinds, slotFilter: slotFilter, snapshot: snapshot)
    }

    private static func searchMode(_ arguments: ScriptValue) throws -> BinarySearchMode {
        guard let value = arguments["mode"], value != .null else { return .text }
        guard let text = value.stringValue, let mode = BinarySearchMode(rawValue: text) else {
            throw ScriptingError.invalidArgument("search mode must be text, regex or hex")
        }
        return mode
    }

    private static func searchSynchronously(
        _ arguments: ScriptValue, store: WorkspaceStore, validateDirectHex: Bool
    ) throws -> ScriptValue {
        if let cursor = arguments["cursor"], cursor != .null {
            throw ScriptingError.invalidArgument("cursor is accepted only by the bounded search")
        }
        let query = try string(arguments, "query")
        let mode = try searchMode(arguments)
        let snapshot = store.snapshot
        var scope = searchScope(
            filter: try resolveImageSlotFilter(arguments, snapshot: snapshot),
            focusedSlot: store.focusedImageSlot)
        if let kind = try searchKind(arguments, mode: mode) { scope.kinds = [kind] }
        if (mode == .regex || (validateDirectHex && mode == .hex)),
           let detail = BinarySearchService().validate(query: query, mode: mode) {
            throw ScriptingError.invalidArgument(detail)
        }
        let outcome = BinarySearchService().searchWithCount(query: query, mode: mode, in: snapshot, scope: scope)
        return .object([
            "total": .int(Int64(outcome.total)),
            "results": .array(outcome.results.map(searchRow)),
        ])
    }

    /// A selector narrows the scan before the engine spends its shared visit budget.
    /// Keep this check shared by synchronous and asynchronous command entry points.
    static func searchKind(
        _ arguments: ScriptValue, mode: BinarySearchMode
    ) throws -> BinarySearchResult.Kind? {
        guard let value = arguments["kind"] else { return nil }
        guard let text = value.stringValue,
              let kind = BinarySearchResult.Kind(rawValue: text),
              (mode == .hex ? kind == .bytes : kind != .bytes) else {
            throw ScriptingError.invalidArgument(
                "search kind must be bytes for mode hex, or instruction, string, symbol, function for text/regex")
        }
        return kind
    }

    /// Runs one heavy read over an immutable snapshot captured on MainActor. The detached
    /// task is owned by this request: parent cancellation cancels it, each checkpoint throws
    /// `CancellationError`, and a cancelled read never publishes a partial result. Read-only,
    /// so discarding a result that completed concurrently with cancellation is truthful.
    private func executeSnapshotRead(
        _ read: ScriptingSnapshotRead,
        arguments: ScriptValue
    ) async throws -> ScriptValue {
        try Task.checkCancellation()
        let probe = snapshotReadCheckpoint
        let native = read == .decompile ? nativeDecompiler : nil
        let deadline = read == .decompile ? decompileDeadlineNanoseconds : nil
        let trace: NativeDecompilerPhaseRecord?
        if native == nil {
            trace = nil
        } else if let phaseAttempt {
            trace = phaseAttempt()
        } else {
            trace = NativeDecompilerPhaseRecord.makeAttempt()
        }
        defer { trace?.finish() }
        let rootSpan = trace?.begin(.snapshotRead)
        defer { trace?.end(rootSpan) }
        let captureSpan = trace?.begin(.snapshotCapture)
        let context = ScriptingSnapshotReadContext(
            snapshot: store.snapshot, focusedSlot: store.focusedImageSlot
        )
        ScriptingGenerationCapture.current?.record(context.snapshot.analysisGenerationID)
        trace?.end(captureSpan)
        let cancellation = PseudocodeRenderingThread.Cancellation()
        let output: ScriptValue
        do {
            let waitSpan = trace?.begin(.detachedWait)
            defer { trace?.end(waitSpan) }
            let work = Task.detached(priority: Task.currentPriority) {
                let checkpoint: @Sendable () throws -> Void = {
                    probe?()
                    try cancellation.check()
                    try Task.checkCancellation()
                }
                if let native {
                    if let trace {
                        return try await NativeDecompilerPhaseRecord.withTrace(trace) {
                            try await WorkspaceScriptingAPI.decompileNativeFirst(
                                arguments, snapshot: context.snapshot, native: native,
                                checkpoint: checkpoint, trace: trace
                            )
                        }
                    }
                    return try await WorkspaceScriptingAPI.decompileNativeFirst(
                        arguments, snapshot: context.snapshot, native: native, checkpoint: checkpoint
                    )
                }
                if read == .decompile {
                    return try await PseudocodeRenderingThread.run {
                        try WorkspaceScriptingAPI.runSnapshotRead(
                            read, arguments: arguments, context: context, checkpoint: checkpoint
                        )
                    }
                }
                if read == .parameterBindingAudit {
                    return try await PseudocodeRenderingThread.runLifting {
                        try WorkspaceScriptingAPI.runSnapshotRead(
                            read, arguments: arguments, context: context, checkpoint: checkpoint
                        )
                    }
                }
                return try WorkspaceScriptingAPI.runSnapshotRead(
                    read, arguments: arguments, context: context, checkpoint: checkpoint
                )
            }
            output = try await withTaskCancellationHandler {
                try await Self.awaitSnapshotRead(work, deadlineNanoseconds: deadline) { cancellation.cancel(); work.cancel() }
            } onCancel: {
                cancellation.cancel()
                work.cancel()
            }
        }
        try Task.checkCancellation()
        return output
    }

    /// The single implementation of each snapshot read. The synchronous registry passes a
    /// no-op checkpoint, so async and legacy results are produced by the same code.
    nonisolated static func runSnapshotRead(
        _ read: ScriptingSnapshotRead,
        arguments: ScriptValue,
        context: ScriptingSnapshotReadContext,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        switch read {
        case .annotationGaps:
            return try annotationGapsRead(snapshot: context.snapshot, checkpoint: checkpoint)
        case .decompile:
            let choice = try decompileBackendChoice(arguments)
            if choice == .native {
                _ = try decompileShape(arguments)
                let slot = try resolveImageSlot(arguments, snapshot: context.snapshot)
                let function = try resolveDecompileFunction(arguments, in: slot, snapshot: context.snapshot)
                try decompileSizeCheck(function, in: slot, snapshot: context.snapshot, checkpoint: checkpoint)
                throw nativeBackendRefusal(cause: ScriptingNativeFallbackCause.notBound, detail: "no-native-binding")
            }
            let macir = try decompileObject(arguments, snapshot: context.snapshot,
                requested: choice != nil, checkpoint: checkpoint)
            if choice == .both {
                return pairedDecompileReply(native: .object([
                    "fallbackReason": .string(ScriptingDecompileBackend.nativeUnavailable),
                    "fallbackCause": .string(ScriptingNativeFallbackCause.notBound),
                    "fallbackDetail": .string("no-native-binding")]), macir: macir)
            }
            return macir
        case .parameterBindingAudit:
            return try parameterBindingAuditRead(arguments, snapshot: context.snapshot,
                slot: context.focusedSlot, checkpoint: checkpoint)
        case .basicBlocks:
            return try basicBlocksObject(arguments, snapshot: context.snapshot, checkpoint: checkpoint)
        }
    }

    /// Inventory stored authoring, never inferred names/comments or imported prototypes.
    /// Address pairs stay image-qualified, including retained overrides for unloaded images.
    /// "Unapplied" describes the current catalog/application state, not edit history.
    nonisolated static func annotationGapsRead(
        snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        try checkpoint()
        var functionStarts: [ImageSlot: Set<UInt64>] = [:]
        for (slot, analysis) in snapshot.analysisBySlot {
            var starts = Set<UInt64>()
            for function in analysis.functions {
                try checkpoint()
                starts.insert(function.startAddress)
            }
            functionStarts[slot] = starts
        }

        var renamedFunctionsWithoutComment: [ScriptValue] = []
        var signaturesWithoutRename: [ScriptValue] = []
        var appliedTypeNames = Set<String>()
        let keys = snapshot.addressOverrides.keys.sorted {
            $0.slot.rawValue == $1.slot.rawValue
                ? $0.address < $1.address : $0.slot.rawValue < $1.slot.rawValue
        }
        for key in keys {
            try checkpoint()
            guard let override = snapshot.addressOverrides[key] else { continue }
            if let name = override.appliedTypeName { appliedTypeNames.insert(name) }
            let name = override.customName?.trimmingCharacters(in: .whitespacesAndNewlines)
            let hasName = !(name?.isEmpty ?? true)
            let hasComment = !(override.customComment?
                .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            let functionKnown = functionStarts[key.slot]?.contains(key.address) ?? false
            let provenance: [String: ScriptValue] = [
                "address": .hex(key.address),
                "imageSlot": .int(Int64(key.slot.rawValue)),
                "imageOwner": snapshot.binary(in: key.slot).map { .string($0.id.uuidString) } ?? .null,
                "functionKnown": .bool(functionKnown),
            ]
            if functionKnown, hasName, !hasComment {
                var row = provenance
                row["name"] = name.map(ScriptValue.string) ?? .null
                renamedFunctionsWithoutComment.append(.object(row))
            }
            if let signature = override.signature, !signature.isEmpty, !hasName {
                signaturesWithoutRename.append(.object(provenance))
            }
        }

        var unappliedTypes: [ScriptValue] = []
        let types = snapshot.typeDefinitions.sorted {
            $0.name == $1.name ? $0.id.uuidString < $1.id.uuidString : $0.name < $1.name
        }
        for type in types {
            try checkpoint()
            if !appliedTypeNames.contains(type.name) {
                unappliedTypes.append(.object([
                    "id": .string(type.id.uuidString),
                    "name": .string(type.name),
                    "kind": .string(type.kind.rawValue),
                ]))
            }
        }
        try checkpoint()
        return .object([
            "scope": .string("workspace"),
            "renamedFunctionsWithoutComment": .array(renamedFunctionsWithoutComment),
            "unappliedTypes": .array(unappliedTypes),
            "signaturesWithoutRename": .array(signaturesWithoutRename),
        ])
    }

    /// Native-first `decompile`: asks the native runtime for the function the selector resolves
    /// to in the selected image (the primary image unless `image` names another; the same
    /// binding MacIR uses), and falls back to MacIR when native is unavailable, fails, or
    /// returns no document. Cancellation observed after the native await throws instead of
    /// falling back. Checkpoints cover entry, the size scan, after the native await,
    /// and the MacIR path on fallback.
    nonisolated static func decompileNativeFirst(
        _ arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        native: any ScriptingNativeDecompiling,
        checkpoint: @escaping @Sendable () throws -> Void,
        trace: NativeDecompilerPhaseRecord? = nil
    ) async throws -> ScriptValue {
        try checkpoint()
        let choice: DecompileBackendChoice?
        let shape: DecompileShape?
        let slot: ImageSlot
        let function: FunctionSummary
        do {
            let selectorSpan = trace?.begin(.selector)
            defer { trace?.end(selectorSpan) }
            choice = try decompileBackendChoice(arguments)
            shape = try decompileShape(arguments)
            slot = try resolveImageSlot(arguments, snapshot: snapshot)
            function = try resolveDecompileFunction(arguments, in: slot, snapshot: snapshot)
        }
        do {
            let sizeSpan = trace?.begin(.sizeCheck)
            defer { trace?.end(sizeSpan) }
            try decompileSizeCheck(function, in: slot, snapshot: snapshot, checkpoint: checkpoint)
        }
        if choice == .macir {
            return try await PseudocodeRenderingThread.run {
                try decompileObject(arguments, snapshot: snapshot, requested: true, checkpoint: checkpoint)
            }
        }
        // E4: native ignores folds, so an implicit route goes to MacIR and says so.
        if choice == nil, !(try decompileFold(arguments)).isEmpty {
            return try await PseudocodeRenderingThread.run {
                try decompileObject(arguments, snapshot: snapshot, requested: false, checkpoint: checkpoint)
            }
        }
        // E2: native text cannot carry authored comments. A function that has some is served by MacIR
        // with the cause disclosed; an explicit native request is refused (typed); `both` keeps the
        // native half unmodified and says so.
        let hasUserComments: Bool
        do {
            let commentsSpan = trace?.begin(.comments)
            defer { trace?.end(commentsSpan) }
            hasUserComments = try functionHasUserComments(function, in: slot, snapshot: snapshot, checkpoint: checkpoint)
        }
        if hasUserComments, choice == .native {
            throw nativeBackendRefusal(cause: ScriptingNativeFallbackCause.userComments,
                detail: "native text cannot place authored comments")
        }
        if hasUserComments, choice == nil {
            return try await PseudocodeRenderingThread.run {
                try decompileObject(arguments, snapshot: snapshot,
                    fallbackReason: ScriptingDecompileBackend.userComments,
                    fallbackCause: ScriptingNativeFallbackCause.userComments,
                    fallbackDetail: "authored-comments-in-range", requested: false, checkpoint: checkpoint)
            }
        }
        let disclosure = await native.decompileDisclosed(ScriptingNativeDecompileRequest(
            snapshot: snapshot,
            imageSlot: slot,
            functionID: function.id,
            startAddress: function.startAddress
        ))
        try checkpoint()
        let fallbackReason: String
        let cause: String
        let detail: String
        switch disclosure.outcome {
        case .completed(let document?)
            where !document.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty:
            let nativeObjectSpan = trace?.begin(.nativeObject)
            var fields = nativeDecompileObject(function: function,
                displayName: snapshot.displayName(at: function.startAddress, in: slot, default: function.name),
                document: document)
            if let cache = disclosure.cache {
                fields["cache"] = .string(cache)
                fields["generation"] = .string(snapshot.analysisGenerationID.uuidString)
            }
            if choice == .native { fields["backendRequested"] = .string("native") }
            trace?.end(nativeObjectSpan)
            let finalShapeSpan = trace?.begin(.finalShape)
            defer { trace?.end(finalShapeSpan) }
            if let shape {
                let nativeLines = fields["lines"]?.arrayValue ?? []
                fields = try shapedDecompileFields(fields, shape: shape, slot: slot,
                    functionStart: function.startAddress, snapshot: snapshot,
                    backend: ScriptingDecompileBackend.native, fullText: document.text,
                    lineCount: nativeLines.count,
                    textAt: { nativeLines[$0]["text"]?.stringValue ?? "" }, lineAt: { nativeLines[$0] },
                    nativeDocumentTruncated: document.isTruncated, checkpoint: checkpoint)
            }
            fields.merge(imageProvenanceFields(slot: slot, snapshot: snapshot)) { _, label in label }
            let reply = functionReply(.object(fields), arguments: arguments, function: function)
            let source = shape.map { _ in
                DecompileReplySource(text: document.text, lines: document.text.split(
                    separator: "\n", omittingEmptySubsequences: false).map(String.init))
            }
            if choice == .both {
                trace?.end(finalShapeSpan)
                return try await PseudocodeRenderingThread.run {
                    try decompileObject(arguments, snapshot: snapshot, requested: true,
                        pairedNative: reply, nativeSource: source,
                        nativeCommentsNotApplied: hasUserComments, checkpoint: checkpoint)
                }
            }
            return try boundedDecompileReply(reply, shape: shape, slot: slot,
                functionStart: function.startAddress, snapshot: snapshot,
                sources: source.map { [ScriptingDecompileBackend.native: $0] } ?? [:])
        case .completed:
            fallbackReason = ScriptingDecompileBackend.nativeEmpty
            cause = ScriptingNativeFallbackCause.error
            detail = "native-empty"
        case .unavailable:
            fallbackReason = ScriptingDecompileBackend.nativeUnavailable
            cause = disclosure.cause ?? ScriptingNativeFallbackCause.unknown
            detail = disclosure.detail ?? "native-unavailable"
        case .failed(let code):
            fallbackReason = ScriptingDecompileBackend.nativeFailed(code)
            let classified = ScriptingNativeFallbackCause.classify(code: code)
            cause = disclosure.cause ?? classified.cause
            detail = disclosure.detail ?? classified.detail
        }
        if choice == .native { throw nativeBackendRefusal(cause: cause, detail: detail) }
        let pairedNative: ScriptValue? = choice == .both ? .object([
            "fallbackReason": .string(fallbackReason), "fallbackCause": .string(cause),
            "fallbackDetail": .string(detail)]) : nil
        return try await PseudocodeRenderingThread.run {
            try decompileObject(arguments, snapshot: snapshot, fallbackReason: fallbackReason,
                fallbackCause: cause, fallbackDetail: detail, requested: choice == .both,
                pairedNative: pairedNative, nativeCommentsNotApplied: hasUserComments,
                checkpoint: checkpoint)
        }
    }

    nonisolated private static func nativeDecompileObject(
        function: FunctionSummary, displayName: String,
        document: NativeDecompilerWirePseudocodeDocument
    ) -> [String: ScriptValue] {
        var lines: [ScriptValue] = []
        for (index, text) in document.text.split(
            separator: "\n", omittingEmptySubsequences: false
        ).enumerated() {
            lines.append(.object(["n": .int(Int64(index + 1)), "text": .string(String(text))]))
        }
        var fields: [String: ScriptValue] = [
            "function": .string(displayName),
            "address": .hex(function.startAddress),
            "pseudocode": .string(document.text),
            "structured": .bool(false),
            "lines": .array(lines),
            "backend": .string(ScriptingDecompileBackend.native),
            "language": .string(document.language),
            "complete": .bool(document.isComplete),
            "truncated": .bool(document.isTruncated),
            // Unshaped replies contain all rendered lines; shaping may narrow this claim.
            "responseComplete": .bool(document.isComplete && !document.isTruncated),
        ]
        if let demangled = scriptingDemangled(displayName) { fields["demangled"] = .string(demangled) }
        return fields
    }

    /// `decompile`'s function binding in the selected image. For the primary slot (the MS-06
    /// default) this is exactly the primary-image resolver; for a sibling it reads functions and
    /// display names from that image only, with the same name/address selector policy.
    nonisolated private static func resolveDecompileFunction(
        _ arguments: ScriptValue,
        in slot: ImageSlot,
        snapshot: WorkspaceSnapshot
    ) throws -> FunctionSummary {
        try resolveFunction(
            arguments, in: snapshot.analysis(in: slot)?.functions ?? [], slot: slot, snapshot: snapshot
        )
    }

    /// Checkpoints: entry, during the size scan, after body extraction, after MacIR build, inside the printer every
    /// `PseudocodePrinter.cancellationCheckpointInterval` emission steps (statements, region
    /// entries, structured instructions), after print, and every 1,024 serialized lines. The
    /// size scan visits at most 1,024 blocks between cooperative checks.
    nonisolated private static func decompileObject(
        _ arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        fallbackReason: String = ScriptingDecompileBackend.nativeUnavailable,
        fallbackCause: String = ScriptingNativeFallbackCause.notBound,
        fallbackDetail: String = "no-native-binding",
        requested: Bool = false,
        pairedNative: ScriptValue? = nil,
        nativeSource: DecompileReplySource? = nil,
        nativeCommentsNotApplied: Bool = false,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        try checkpoint()
        let shape = try decompileShape(arguments)
        let foldKinds = try decompileFold(arguments)
        // Every per-image input below reads `slot`: the primary image by default, so the
        // primary-slot path is the pre-MS-19 computation unchanged.
        let slot = try resolveImageSlot(arguments, snapshot: snapshot)
        let function = try resolveDecompileFunction(arguments, in: slot, snapshot: snapshot)
        try decompileSizeCheck(function, in: slot, snapshot: snapshot, checkpoint: checkpoint)
        let resolution = try snapshot.pseudocodeTargetResolved(
            selectedAddress: function.startAddress, in: slot, includeUserComments: true, checkpoint: checkpoint)
        let target = resolution.map { (function: $0.function, instructions: $0.instructions) }
        // E2: over a cap the whole decompile is refused here, before any output is built.
        try enforceUserCommentBudget(resolution?.userComments ?? [:])
        let machineUsage = snapshot.machineCallUsageHandoff(for: target, in: slot)
        try checkpoint()
        // Exactly the two phases of `PseudocodePrinter.print(functionName:...)`, split so
        // cancellation is observed between the MacIR build and rendering.
        let printer = PseudocodePrinter()
        let irFunction = printer.buildFunction(
            functionName: snapshot.displayName(at: function.startAddress, in: slot, default: function.name),
            startAddress: function.startAddress,
            jumpTables: snapshot.resolvedJumpTables(in: slot),
            objcSelectors: snapshot.analysis(in: slot)?.objcSelectors ?? [:],
            constantStrings: snapshot.constantStrings(in: slot),
            signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
            authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
            directCallVoidResultTargets: snapshot.directCallVoidResultTargets(in: slot),
            machineCallUsage: machineUsage?.usage,
            machineUsageContext: machineUsage?.context,
            types: snapshot.typeDefinitions,
            instructions: target?.instructions ?? []
        )
        try checkpoint()
        let foldRequest: PseudocodeFoldRequest? = foldKinds.isEmpty ? nil : PseudocodeFoldRequest(
            kinds: foldKinds,
            arcCallSites: foldKinds.contains(.arc) ? snapshot.arcFoldCallSites(for: target, in: slot) : [:])
        let document = try printer.print(
            function: irFunction,
            ownDirectCallAddresses: snapshot.ownDirectCallAddresses(in: slot),
            types: snapshot.typeDefinitions,
            nameOverrides: snapshot.functionNameOverrides(in: slot),
            registerNameOverrides: snapshot.registerNameOverrides(forProcedureAt: function.startAddress, in: slot),
            stackLocalOverrides: snapshot.stackLocalOverrides(forProcedureAt: function.startAddress, in: slot),
            fold: foldRequest,
            userComments: PseudocodeUserComments(
                textByAddress: resolution?.userComments ?? [:],
                bodyAddresses: Set((target?.instructions ?? []).map(\.address)),
                excludedAddresses: snapshot.codeExcludedAddresses(in: slot)),
            checkpoint: checkpoint
        )
        try checkpoint()
        var lines: [ScriptValue] = []
        if shape == nil {
            lines.reserveCapacity(document.lines.count)
            for (index, line) in document.lines.enumerated() {
                if index > 0, index.isMultiple(of: 1_024) { try checkpoint() }
                lines.append(pseudocodeLineObject(line))
            }
        }
        var fields: [String: ScriptValue] = [
            "function": .string(snapshot.displayName(at: function.startAddress, in: slot, default: function.name)),
            "address": .hex(function.startAddress),
            "pseudocode": .string(document.text),
            "structured": .bool(document.regionTree != nil),
            "lines": .array(lines),
            "backend": .string(ScriptingDecompileBackend.macIR),
        ]
        if requested {
            fields["backendRequested"] = .string("macir")
        } else if !foldKinds.isEmpty {
            fields["fallbackReason"] = .string("fold-requires-macir")
            fields["fallbackCause"] = .string(ScriptingNativeFallbackCause.notApplicable)
            fields["fallbackDetail"] = .string("native-ignores-fold")
        } else {
            fields["fallbackReason"] = .string(fallbackReason)
            fields["fallbackCause"] = .string(fallbackCause)
            fields["fallbackDetail"] = .string(fallbackDetail)
        }
        if let name = fields["function"]?.stringValue, let demangled = scriptingDemangled(name) {
            fields["demangled"] = .string(demangled)
        }
        fields.merge(imageProvenanceFields(slot: slot, snapshot: snapshot)) { _, label in label }
        fields.merge(decompileAnnotationFields(
            comments: resolution?.userComments ?? [:], document: document,
            callTargetNames: resolution?.callTargetNames ?? [])) { _, annotation in annotation }
        if shape?.cursor == nil, let regionTree = document.regionTree {
            fields["regions"] = pseudocodeRegionObject(regionTree)
        }
        if let structureFallback = document.structureFallback {
            fields["structureFallback"] = .string(structureFallback.rawValue)
        }
        if let shape {
            fields = try shapedDecompileFields(fields, shape: shape, slot: slot,
                functionStart: function.startAddress, snapshot: snapshot,
                backend: ScriptingDecompileBackend.macIR, fullText: document.text,
                lineCount: document.lines.count, textAt: { document.lines[$0].text },
                lineAt: { pseudocodeLineObject(document.lines[$0]) },
                foldMode: foldKinds.isEmpty ? nil : foldModeText(foldKinds), checkpoint: checkpoint)
        }
        if !foldKinds.isEmpty {
            applyFoldFields(&fields, kinds: foldKinds, report: document.foldReport)
            try applyFoldComparisonFields(&fields, printer: printer, irFunction: irFunction, snapshot: snapshot, slot: slot, function: function, resolution: resolution, target: target, foldedLineCount: document.lines.count, checkpoint: checkpoint)
        }
        let reply = functionReply(.object(fields), arguments: arguments, function: function)
        let output: ScriptValue
        if let pairedNative {
            output = pairedDecompileReply(native: pairedNative, macir: reply,
                nativeCommentsNotApplied: nativeCommentsNotApplied)
        } else { output = reply }
        guard shape != nil else { return output }
        var sources: [String: DecompileReplySource] = [
            ScriptingDecompileBackend.macIR: .init(text: document.text, lines: document.lines.map(\.text))
        ]
        if let nativeSource { sources[ScriptingDecompileBackend.native] = nativeSource }
        return try boundedDecompileReply(output, shape: shape, slot: slot,
            functionStart: function.startAddress, snapshot: snapshot, sources: sources,
            foldMode: foldKinds.isEmpty ? nil : foldModeText(foldKinds), refreshPage: { page in
                if !foldKinds.isEmpty { applyFoldFields(&page, kinds: foldKinds, report: document.foldReport) }
            })
    }

    /// Checkpoints: entry, every 4,096 scanned image instructions, after body extraction,
    /// after MacIR build, and after the audit.
    nonisolated private static func parameterBindingAuditRead(
        _ arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        slot: ImageSlot,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        try checkpoint()
        guard let analysis = snapshot.analysis(in: slot) else {
            throw ScriptingError.invalidArgument("no analyzed image exists in the focused slot")
        }
        let function = try resolveFunction(
            arguments, in: analysis.functions, slot: slot, snapshot: snapshot
        )
        let overrides = snapshot.overrides(in: slot)
        var instructions: [InstructionRow] = []
        for (index, row) in analysis.instructions.enumerated() {
            if index > 0, index.isMultiple(of: 4_096) { try checkpoint() }
            let isExcludedFromCode = overrides[row.address].map {
                $0.isData || $0.isUndefined || !($0.dataShape?.isEmpty ?? true)
            } ?? false
            guard row.address >= function.startAddress, !isExcludedFromCode else { continue }
            let inBody = function.endAddress > function.startAddress
                ? row.address < function.endAddress
                : row.address == function.startAddress
            if inBody { instructions.append(row) }
        }
        try checkpoint()
        let irFunction = PseudocodePrinter().buildFunction(
            functionName: snapshot.displayName(
                at: function.startAddress,
                in: slot,
                default: function.name
            ),
            startAddress: function.startAddress,
            jumpTables: snapshot.resolvedJumpTables(in: slot),
            objcSelectors: analysis.objcSelectors,
            signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
            authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
            types: snapshot.typeDefinitions,
            instructions: instructions
        )
        try checkpoint()
        let audit = irFunction.parameterBindingAudit()
        try checkpoint()
        return functionReply(parameterBindingAuditObject(audit), arguments: arguments, function: function)
    }

    /// Successor discovery scans every image control-flow edge once per block, so the
    /// per-block checkpoint bounds post-cancellation work to one edge scan.
    nonisolated private static func basicBlocksObject(
        _ arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        try checkpoint()
        let function = try resolveFunction(arguments, snapshot)
        // Use the canonical `functionRange` (the same bound `callers`/`callees` use) so a
        // zero-width function still contains its own start block instead of yielding [].
        let range = snapshot.functionRange(function)
        let blocks = snapshot.basicBlocks
            .filter { range.contains($0.startAddress) }
            .sorted { $0.startAddress < $1.startAddress }
        let edges = snapshot.controlFlowEdges
        var values: [ScriptValue] = []
        values.reserveCapacity(blocks.count)
        for block in blocks {
            try checkpoint()
            let successors = edges
                .filter { $0.from >= block.startAddress && $0.from < block.endAddress }
                .map { ScriptValue.object(["to": .hex($0.to), "kind": .string($0.kind)]) }
            values.append(.object([
                "start": .hex(block.startAddress),
                "end": .hex(block.endAddress),
                "instructionCount": .int(Int64(block.instructionCount)),
                "successors": .array(successors),
            ]))
        }
        return .array(values)
    }

    /// Runs a batch script: an array of `{ "command": ..., "arguments": {...} }` steps,
    /// returning each result in order. This is the primitive a Python/MCP/CLI client
    /// sends; a single round-trip drives a whole automation sequence.
    func runScript(_ script: ScriptValue) throws -> ScriptValue {
        guard let steps = script.arrayValue else {
            throw ScriptingError.invalidArgument("a script must be a JSON array of steps")
        }
        var results: [ScriptValue] = []
        var history = ScriptingBatchHistory()
        do {
            for step in steps {
                guard let command = step["command"]?.stringValue else {
                    throw ScriptingError.missingArgument("command")
                }
                // Reject a present-but-non-object `arguments`. Otherwise a misencoded step
                // (e.g. `"arguments": 5`) would pass straight through — every argument
                // lookup misses, so a read command silently runs with its defaults (e.g.
                // an unbounded result set) instead of reporting the malformed step.
                let arguments: ScriptValue
                switch step["arguments"] {
                case .none, .some(.null):
                    arguments = .object([:])
                case let .some(value):
                    guard case .object = value else {
                        throw ScriptingError.invalidArgument("step 'arguments' must be a JSON object")
                    }
                    arguments = value
                }
                let capture = ScriptingBatchReceiptCapture()
                let value = try ScriptingBatchReceiptCapture.$current.withValue(capture) { try execute(command, arguments: arguments) }
                if MCPBatchReceiptBudget.commands.contains(command), let count = value["count"]?.intValue,
                   let changed = value["changed"]?.intValue {
                    history.record(command: command, count: count, changed: changed,
                                   imageSlot: capture.receipt?.imageSlot ?? value["imageSlot"]?.intValue)
                }
                results.append(value)
            }
            return .array(results)
        } catch {
            throw history.failure(error)
        }
    }

    /// The introspectable command surface (sorted by name).
    static var availableCommands: [ScriptingCommandInfo] {
        registry.values.map { $0.info.withEvidencePrecondition }.sorted { $0.name < $1.name }
    }

    // MARK: - Registry

    static func readEvidenceOperation(_ arguments: ScriptValue) throws -> TypedReadRegistry.ExternalOperation {
        guard case .object(let fields) = arguments, Set(fields.keys) == ["operation"],
              let rawValue = fields["operation"]?.stringValue,
              let operation = TypedReadRegistry.ExternalOperation(rawValue: rawValue) else {
            throw ScriptingError.invalidArgument("read-evidence requires one supported operation")
        }
        return operation
    }

    private static func readEvidence(
        _ arguments: ScriptValue,
        store: WorkspaceStore,
        proposingPrincipal: Phase2Principal
    ) throws -> ScriptValue {
        let operation = try readEvidenceOperation(arguments)
        switch store.preparePhase2Read(operation: operation.operationID, proposingPrincipal: proposingPrincipal) {
        case .prepared(let prepared):
            if proposingPrincipal == .cli || proposingPrincipal == .mcp {
                // Each external call creates its own invocation and accepts no
                // caller-supplied replay handle. Its acceptance lives only until
                // this response is encoded, including transport rejection paths.
                var invocationAcceptor = Phase2EvidenceAcceptor()
                let execution = store.executePhase2Read(prepared, acceptingWith: &invocationAcceptor)
                return try readEvidenceResult(execution, authorization: prepared.authorization)
            }
            return try readEvidenceResult(store.executePhase2Read(prepared), authorization: prepared.authorization)
        case .unavailable(let reason):
            return .object([
                "schemaVersion": .int(1), "operation": .string(operation.rawValue),
                "status": .string("unavailable"), "reason": .string(reason.rawValue),
            ])
        case .rejected(let disposition):
            return .object([
                "schemaVersion": .int(1), "operation": .string(operation.rawValue),
                "status": .string("unavailable"), "reason": .string(disposition.rawValue),
            ])
        }
    }

    /// Only the app-accepted record supplies facts. Delayed, duplicate, cancelled,
    /// or stale candidates remain unavailable and never expose candidate data.
    static func readEvidenceResult(
        _ execution: Phase2ReadExecution,
        authorization: Phase2ReadAuthorization
    ) throws -> ScriptValue {
        var output: [String: ScriptValue] = [
            "schemaVersion": .int(1),
            "operation": .string(authorization.canonicalDescriptor.id.rawValue),
            "disposition": .string(execution.disposition.rawValue),
            "status": .string("unavailable"),
        ]
        guard authorization.isValid else {
            output["reason"] = .string("unauthorized")
            return .object(output)
        }
        guard TypedReadRegistry.ExternalOperation(rawValue: authorization.canonicalDescriptor.id.rawValue) != nil else {
            output["reason"] = .string("unsupported")
            return .object(output)
        }
        guard execution.disposition == .accepted,
              let evidence = execution.acceptedEvidence,
              execution.outcome.evidenceIDs == [evidence.evidenceID],
              evidence.candidateID == execution.candidate.candidateID,
              evidence.invocationID == authorization.request.invocationID,
              evidence.sequence == authorization.request.sequence,
              evidence.descriptor == authorization.canonicalDescriptor,
              evidence.precondition == authorization.request.precondition,
              evidence.data == execution.candidate.data else {
            output["reason"] = .string(execution.disposition.rawValue)
            return .object(output)
        }
        output["proposingPrincipal"] = .string(readPrincipalName(authorization.request.proposingPrincipal))
        output["authorizingPrincipal"] = .string(readPrincipalName(authorization.authorizingPrincipal))
        output["producingPrincipal"] = .string(readPrincipalName(evidence.producingPrincipal))
        output["evidenceID"] = .string(evidence.evidenceID.uuidString)
        output["invocationID"] = .string(evidence.invocationID.uuidString)
        output["sequence"] = .string(String(evidence.sequence))
        output["payloadDigest"] = .string(evidence.payloadDigest)
        output["descriptor"] = try exactReadJSON(evidence.descriptor)
        output["subject"] = try exactReadJSON(authorization.request.subject)
        output["precondition"] = try exactReadJSON(evidence.precondition)
        output["citations"] = try exactReadJSON(evidence.citations)
        switch evidence.data {
        case .value(let value):
            output["status"] = .string("accepted")
            output["facts"] = try readFacts(value)
        case .unavailable(let reason):
            output["reason"] = .string(reason.rawValue)
        case .conflict:
            // This adapter's three operations do not publish conflicts as facts.
            output["reason"] = .string("conflict")
        }
        return .object(output)
    }

    private static func readPrincipalName(_ principal: Phase2Principal) -> String {
        switch principal {
        case .app: "app"
        case .human: "human"
        case .model: "model"
        case .cli: "cli"
        case .mcp: "mcp"
        default: "unavailable"
        }
    }

    private static func readFacts(_ value: Phase2ReadFactValue) throws -> ScriptValue {
        switch value {
        case .boolean(let value): return .bool(value)
        case .signedInteger(let value): return .string(String(value))
        case .unsignedInteger(let value): return .string(String(value))
        case .text(let value): return .string(value)
        case .staticLocation(let value): return try exactReadJSON(value)
        case .list(let values): return .array(try values.map(readFacts))
        case .object(let fields):
            var object: [String: ScriptValue] = [:]
            for field in fields { object[field.name] = try readFacts(field.value) }
            return .object(object)
        }
    }

    /// `reconstruction-jobs`: the pure `ReconstructionJobStatusSummary` of every durable job (or the
    /// one named by `job`), newest creation first. Numbers are exact decimal strings.
    static func reconstructionJobsStatus(_ arguments: ScriptValue,
        state: ReconstructionWorkspaceState,
        lifecycle: ReconstructionLifecycleTimestamps = .empty) throws -> ScriptValue {
        let jobIDs: [UUID]
        if let raw = arguments["job"]?.stringValue {
            guard let jobID = UUID(uuidString: raw), state.jobs.contains(where: { $0.jobID == jobID }) else {
                throw ScriptingError.invalidArgument("job must name an existing Reconstruction job UUID")
            }
            jobIDs = [jobID]
        } else {
            jobIDs = state.jobs.sorted { ($0.creationOrdinal ?? 0) > ($1.creationOrdinal ?? 0) }.map(\.jobID)
        }
        return .array(try jobIDs.prefix(64).compactMap { jobID in
            try ReconstructionJobStatusSummary.make(jobID: jobID, state: state, lifecycle: lifecycle).map(exactReadJSON)
        })
    }

    /// Codable metadata is parsed as exact number lexemes and rendered as decimal
    /// strings. Neither UInt64 addresses nor revision identities cross Double/NSNumber.
    private static func exactReadJSON<Value: Encodable>(_ value: Value) throws -> ScriptValue {
        let bytes = try JSONEncoder().encode(value)
        let json = try Phase2StrictJSONParser().parse(bytes, limits: .init(
            maximumBytes: Phase2ReadLimits.maximum.encodedResultBytes,
            maximumDepth: 32, maximumTokens: 100_000, maximumMembersAndElements: 50_000
        ))
        func convert(_ value: Phase2ProductionJSONValue) -> ScriptValue {
            switch value {
            case .null: return .null
            case .bool(let value): return .bool(value)
            case .number(let source): return .string(source)
            case .string(let value): return .string(value)
            case .array(let values): return .array(values.map(convert))
            case .object(let fields): return .object(fields.mapValues(convert))
            }
        }
        return convert(json)
    }

    private struct Command {
        var info: ScriptingCommandInfo
        var run: @MainActor (ScriptValue, WorkspaceStore) throws -> ScriptValue
    }

    nonisolated static func address(_ arguments: ScriptValue, _ key: String) throws -> UInt64 {
        guard let value = arguments[key] else { throw ScriptingError.missingArgument(key) }
        guard let address = value.addressValue else { throw ScriptingError.invalidArgument("\(key) must be an address") }
        return address
    }

    private static func string(_ arguments: ScriptValue, _ key: String) throws -> String {
        guard let value = arguments[key] else { throw ScriptingError.missingArgument(key) }
        guard let text = value.stringValue else { throw ScriptingError.invalidArgument("\(key) must be a string") }
        return text
    }

    /// A non-negative row cap from the `limit` argument (nil = no limit). A negative
    /// value is clamped to 0 so it can never trap `Collection.prefix(_:)`, which
    /// requires a non-negative length.
    nonisolated static func rowLimit(_ arguments: ScriptValue) throws -> Int? {
        guard let value = arguments["limit"], value != .null else { return nil }
        let integer: Int64?
        switch value {
        case .int(let value): integer = value
        case .double(let value): integer = Int64(exactly: value)
        default: integer = nil
        }
        guard let integer else {
            throw ScriptingError.invalidArgument("limit must be an exact integer in the Int64 range")
        }
        return Int(max(0, integer))
    }

    /// Validates the bounded C type-name subset accepted by scripted signature
    /// authoring. This is deliberately a syntax seam, not an ABI classifier:
    /// opaque identifiers, record types, and fixed/unsized arrays are valid here
    /// even when `DarwinARM64ParameterBinder` later leaves them unbound.
    ///
    /// Accepted forms are an optionally-qualified scalar/opaque/record base,
    /// followed by zero or more qualified `*` levels and then zero or more `[]`
    /// or decimal `[N]` suffixes. Parenthesized/function/block declarators,
    /// expressions in array bounds, and non-ASCII extension spellings are outside
    /// this conservative grammar and fail before any workspace mutation.
    private static func isValidSignatureParameterType(_ source: String) -> Bool {
        guard let tokens = signatureParameterTypeTokens(source), !tokens.isEmpty else {
            return false
        }

        var position = 0
        var baseWords: [String] = []
        while position < tokens.count,
              case let .identifier(word) = tokens[position] {
            baseWords.append(word)
            position += 1
        }
        guard isValidSignatureParameterBase(baseWords) else { return false }

        var pointerCount = 0
        while position < tokens.count, tokens[position] == .star {
            pointerCount += 1
            position += 1
            while position < tokens.count,
                  case let .identifier(qualifier) = tokens[position],
                  signaturePointerQualifiers.contains(qualifier) {
                position += 1
            }
        }

        while position < tokens.count, tokens[position] == .leftBracket {
            position += 1
            if position < tokens.count, tokens[position] == .decimalNumber {
                position += 1
            }
            guard position < tokens.count, tokens[position] == .rightBracket else {
                return false
            }
            position += 1
        }

        // `void *` is a valid data pointer; a named parameter whose entire type is
        // bare `void` is not a value-bearing parameter row.
        let unqualifiedBase = baseWords.filter { !signatureBaseQualifiers.contains($0) }
        if unqualifiedBase == ["void"], pointerCount == 0 { return false }
        return position == tokens.count
    }

    private enum SignatureParameterTypeToken: Equatable {
        case identifier(String)
        case decimalNumber
        case star
        case leftBracket
        case rightBracket
    }

    private static let signatureParameterTypeMaxBytes = 4_096
    private static let signatureBaseQualifiers: Set<String> = [
        "const", "volatile", "restrict", "__restrict", "__restrict__", "_Atomic",
    ]
    private static let signaturePointerQualifiers: Set<String> = [
        "const", "volatile", "restrict", "__restrict", "__restrict__",
    ]
    private static let signatureRecordKeywords: Set<String> = ["struct", "union", "enum"]
    private static let signatureFundamentalIntegerWords: Set<String> = [
        "signed", "unsigned", "char", "short", "int", "long",
    ]
    private static let signatureReservedWords: Set<String> = [
        "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
        "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
        "auto", "break", "case", "char", "const", "continue", "default", "do",
        "double", "else", "enum", "extern", "float", "for", "goto", "if",
        "inline", "int", "long", "register", "restrict", "return", "short",
        "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while",
    ]

    private static func signatureParameterTypeTokens(
        _ source: String
    ) -> [SignatureParameterTypeToken]? {
        let bytes = Array(source.utf8)
        guard !bytes.isEmpty, bytes.count <= signatureParameterTypeMaxBytes else {
            return nil
        }

        var tokens: [SignatureParameterTypeToken] = []
        var position = 0
        while position < bytes.count {
            let byte = bytes[position]
            if isASCIISpace(byte) {
                position += 1
                continue
            }
            if isASCIIIdentifierStart(byte) {
                let start = position
                position += 1
                while position < bytes.count, isASCIIIdentifierContinue(bytes[position]) {
                    position += 1
                }
                tokens.append(.identifier(String(decoding: bytes[start..<position], as: UTF8.self)))
                continue
            }
            if isASCIIDigit(byte) {
                position += 1
                while position < bytes.count, isASCIIDigit(bytes[position]) {
                    position += 1
                }
                tokens.append(.decimalNumber)
                continue
            }
            switch byte {
            case 0x2A: tokens.append(.star)         // *
            case 0x5B: tokens.append(.leftBracket) // [
            case 0x5D: tokens.append(.rightBracket)// ]
            default: return nil
            }
            position += 1
        }
        return tokens
    }

    private static func isValidSignatureParameterBase(_ words: [String]) -> Bool {
        let base = words.filter { !signatureBaseQualifiers.contains($0) }
        guard !base.isEmpty else { return false }

        if base.count == 2,
           signatureRecordKeywords.contains(base[0]),
           isSignatureOpaqueIdentifier(base[1]) {
            return true
        }
        if base.count == 1 {
            let word = base[0]
            if word == "void" || word == "bool" || word == "_Bool"
                || word == "float" || word == "double" {
                return true
            }
            if signatureFundamentalIntegerWords.contains(word) {
                return isValidFundamentalIntegerWords(base)
            }
            return isSignatureOpaqueIdentifier(word)
        }
        if Set(base).isSubset(of: signatureFundamentalIntegerWords) {
            return isValidFundamentalIntegerWords(base)
        }
        if base.count == 2, Set(base) == Set(["long", "double"]) {
            return true
        }
        return false
    }

    private static func isValidFundamentalIntegerWords(_ words: [String]) -> Bool {
        let signedCount = words.filter { $0 == "signed" }.count
        let unsignedCount = words.filter { $0 == "unsigned" }.count
        let charCount = words.filter { $0 == "char" }.count
        let shortCount = words.filter { $0 == "short" }.count
        let intCount = words.filter { $0 == "int" }.count
        let longCount = words.filter { $0 == "long" }.count
        guard signedCount <= 1,
              unsignedCount <= 1,
              signedCount + unsignedCount <= 1,
              charCount <= 1,
              shortCount <= 1,
              intCount <= 1,
              longCount <= 2 else {
            return false
        }
        if charCount == 1 {
            return shortCount == 0 && intCount == 0 && longCount == 0
        }
        if shortCount == 1 {
            return charCount == 0 && longCount == 0
        }
        if longCount > 0 {
            return charCount == 0 && shortCount == 0
        }
        return intCount == 1 || signedCount == 1 || unsignedCount == 1
    }

    private static func isSignatureOpaqueIdentifier(_ word: String) -> Bool {
        guard !word.isEmpty, !signatureReservedWords.contains(word) else { return false }
        let bytes = Array(word.utf8)
        guard let first = bytes.first, isASCIIIdentifierStart(first) else { return false }
        return bytes.dropFirst().allSatisfy(isASCIIIdentifierContinue)
    }

    private static func isASCIISpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private static func isASCIIDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
    }

    private static func isASCIIIdentifierStart(_ byte: UInt8) -> Bool {
        byte == 0x5F || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }

    private static func isASCIIIdentifierContinue(_ byte: UInt8) -> Bool {
        isASCIIIdentifierStart(byte) || isASCIIDigit(byte)
    }

    /// Parses a SIGNED rebase delta: a JSON integer (handling negatives), or a string of
    /// the form `[-]0x…` (hex) or `[-]…` (decimal). Returns nil on an unparseable input.
    /// Unlike `addressValue` this MUST accept negatives — a rebase can shift addresses down.
    static func signedDelta(_ value: ScriptValue) -> Int64? {
        if let intValue = value.intValue { return intValue }
        guard let text = value.stringValue else { return nil }
        var body = text.trimmingCharacters(in: .whitespaces)
        guard !body.isEmpty else { return nil }
        var negative = false
        if body.hasPrefix("-") { negative = true; body = String(body.dropFirst()) }
        else if body.hasPrefix("+") { body = String(body.dropFirst()) }
        let magnitude: UInt64?
        if body.lowercased().hasPrefix("0x") {
            magnitude = UInt64(body.dropFirst(2), radix: 16)
        } else {
            magnitude = UInt64(body)
        }
        guard let magnitude else { return nil }
        if negative {
            // -magnitude as Int64, two's-complement safe for the full negative range
            // (including Int64.min, whose magnitude is 2^63 and exceeds Int64.max).
            guard magnitude <= UInt64(Int64.max) + 1 else { return nil }
            return Int64(bitPattern: ~magnitude &+ 1)
        }
        guard magnitude <= UInt64(Int64.max) else { return nil }
        return Int64(magnitude)
    }

    /// Resolves a function from a `function` name argument or an `address` (a function
    /// start, or any address inside a function's range).
    /// Acceptance commits the undoable authoring layer even when derived analysis fails.
    /// Report both outcomes so callers can correct/clear the retained edit rather than
    /// interpreting a thrown error as evidence that the document stayed unchanged.
    private static func committedPatchResult(
        _ address: UInt64, patch: BytePatch, diagnostic: String?
    ) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "ok": .bool(true), "committed": .bool(true), "address": .hex(address),
            "bytes": .string(patch.byteText),
            "reanalysisStatus": .string(diagnostic == nil ? "no-error-reported" : "failed"),
        ]
        if let diagnostic { fields["reanalysisDiagnostic"] = .string(diagnostic) }
        return .object(fields)
    }

    /// Primary-image resolver: the scope of `functions`, `instructions`, `decompile`, the
    /// call graph and register-rename commands (the snapshot's primary convenience projections).
    /// Name writes that these reads observe (`rename`, `rename-register`, `clear-register-name`)
    /// bind to the same `snapshot.primarySlot`, never to live focus, so a rename made while a
    /// sibling image is focused is still the label `functions` lists and the selector resolves.
    nonisolated static func resolveFunction(_ arguments: ScriptValue, _ snapshot: WorkspaceSnapshot) throws -> FunctionSummary {
        try resolveFunction(arguments, in: snapshot.functions, slot: snapshot.primarySlot, snapshot: snapshot)
    }

    /// Call-graph address reads must not turn nearest-preceding navigation into
    /// evidence about a different function. Keep name-selector precedence.
    nonisolated static func requireCallersContainment(
        _ arguments: ScriptValue, function: FunctionSummary
    ) throws {
        guard arguments["function"]?.stringValue == nil,
              let address = arguments["address"]?.addressValue else { return }
        let contains = function.endAddress > function.startAddress
            ? address >= function.startAddress && address < function.endAddress
            : address == function.startAddress
        guard contains else {
            throw ScriptingError.invalidArgument(
                "callers address is outside every known function; use xrefs with to for exact-address references")
        }
    }

    /// Slot-aware resolver for commands that intentionally target a focused image
    /// rather than the snapshot's primary-image convenience projections. Name selectors
    /// match the effective display label in `slot` (the same name `functions` lists, so a
    /// user rename wins) or the raw analysis name, and fail closed on any ambiguity.
    /// Address selectors require containment; zero-width functions match only their start.
    nonisolated private static func resolveFunction(
        _ arguments: ScriptValue,
        in functions: [FunctionSummary],
        slot: ImageSlot,
        snapshot: WorkspaceSnapshot
    ) throws -> FunctionSummary {
        if let name = arguments["function"]?.stringValue {
            return try resolveFunctionName(name, in: functions) { function in
                snapshot.displayName(at: function.startAddress, in: slot, default: function.name)
            }
        }
        if let target = arguments["address"]?.addressValue {
            var selection = ScriptingFunctionAddressSelection(address: target)
            for function in functions { selection.consider(function) }
            NativeDecompilerPhaseRecord.current()?.add(.functionsConsidered, UInt64(functions.count))
            return try selection.resolved(snapshot: snapshot, slot: slot).function
        }
        throw ScriptingError.missingArgument("function or address")
    }

    /// Add selector provenance to object replies without changing array contracts.
    nonisolated static func functionReply(
        _ reply: ScriptValue, arguments: ScriptValue, function: FunctionSummary
    ) -> ScriptValue {
        guard case .object(var fields) = reply else { return reply }
        fields["resolvedFunction"] = .hex(function.startAddress)
        if arguments["function"]?.stringValue == nil, let address = arguments["address"]?.addressValue {
            fields["requestedAddress"] = .hex(address)
            fields["resolution"] = .string(address == function.startAddress ? "exact" : "containing")
        } else {
            fields.removeValue(forKey: "requestedAddress")
            fields["resolution"] = .string("exact")
        }
        return .object(fields)
    }

    /// The general name-selector policy (MS-06). A function is a candidate when `name`
    /// equals its effective display label (user rename / imported name, read in the
    /// command's image scope) OR its raw analysis name, so the listed name round-trips and
    /// unrenamed raw names keep working. More than one candidate — duplicate display labels,
    /// duplicate raw names, or one function's label equal to a different function's raw
    /// name — is rejected with a typed ambiguity error instead of picking array order.
    /// A plain `±[Class selector]` name also matches `±[Class(Category) selector]` names; when
    /// that fallback contributes to more than one candidate, `ambiguousObjCMethodSelector` lists them all.
    /// `call-argument-audit` deliberately does NOT use this: its structural contract
    /// matches raw names only (`resolveCallArgumentAuditFunction`).
    nonisolated static func resolveFunctionName(
        _ name: String,
        in functions: [FunctionSummary],
        displayName: (FunctionSummary) -> String
    ) throws -> FunctionSummary {
        let requested = ObjCMethodNameParts(name)
        var matches: [FunctionSummary] = []
        var hasFallback = false
        for function in functions {
            let display = displayName(function)
            let exact = function.name == name || display == name
            let fallback = !exact && objcCategoryCandidates(requested,
                rawName: function.name, displayName: display)
            if exact || fallback {
                matches.append(function)
                hasFallback = hasFallback || fallback
            }
        }
        NativeDecompilerPhaseRecord.current()?.add(.functionsConsidered, UInt64(functions.count))
        return try resolveObjCCategoryCandidates(name, matches: matches,
            hasFallback: hasFallback, displayName: displayName)
    }

    nonisolated static func instructionObject(_ row: InstructionRow, _ snapshot: WorkspaceSnapshot) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "address": .hex(row.address),
            "bytes": .string(row.bytes),
            "mnemonic": .string(row.mnemonic),
            "operands": .string(row.operands),
        ]
        if let comment = snapshot.displayComment(at: row.address, default: row.comment) {
            fields["comment"] = .string(comment)
        }
        return .object(fields)
    }

    nonisolated private static func pseudocodeLineObject(_ line: PseudocodeLine) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "n": .int(Int64(line.lineNumber)),
            "kind": .string(line.kind.rawValue),
            "text": .string(line.text),
        ]
        if let address = line.sourceAddress {
            fields["address"] = .hex(address)
        }
        return .object(fields)
    }

    nonisolated private static func pseudocodeRegionObject(_ node: PseudocodeRegionNode) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "kind": .string(node.kind.rawValue),
            "startLine": .int(Int64(node.startLine)),
            "endLine": .int(Int64(node.endLine)),
            "children": .array(node.children.map { pseudocodeRegionObject($0) }),
        ]
        if let condition = node.condition {
            fields["condition"] = .string(condition)
        }
        if let conditionSourceAddress = node.conditionSourceAddress {
            fields["conditionAddress"] = .hex(conditionSourceAddress)
        }
        return .object(fields)
    }

    nonisolated private static func parameterBindingAuditObject(
        _ audit: MacIRParameterBindingAudit
    ) -> ScriptValue {
        let records = audit.records.map { record -> ScriptValue in
            .object([
                "function": .string(record.function),
                "declaration_mode": .string(record.declarationMode.rawValue),
                "row_ordinal": .int(Int64(record.rowOrdinal)),
                "binding": record.binding.map(ScriptValue.string) ?? .null,
                "source_position": record.sourcePosition.map { .int(Int64($0)) } ?? .null,
                "location": .string(record.location),
                "evidence": .string(record.evidence),
                "name": .string(record.name),
                "type": .string(record.type),
                "body_uses": .array(record.bodyUses.map { use in
                    .object([
                        "address": .hex(use.address),
                        "occurrence": .int(Int64(use.occurrence)),
                    ])
                }),
            ])
        }
        let danglingBodyUses = audit.danglingBodyUses.map { dangling in
            ScriptValue.object([
                "binding": .string(dangling.binding),
                "address": .hex(dangling.use.address),
                "occurrence": .int(Int64(dangling.use.occurrence)),
            ])
        }
        return .object([
            "schema": .string(MacIRParameterBindingAudit.schema),
            "validation_scope": .string("structural-candidate"),
            "combined_oracle_comparison": .bool(false),
            "function": .string(audit.function),
            "address": .hex(audit.address),
            "declaration_mode": .string(audit.declarationMode.rawValue),
            "records": .array(records),
            "dangling_body_uses": .array(danglingBodyUses),
        ])
    }

    private struct CallArgumentSafeRenderClassification {
        var included: Bool
        var reason: String
    }

    /// One active-runtime sample per MacScope process. Standalone sweep invocations use a
    /// fresh process and the producer independently snapshots/rechecks the same identity.
    private static var cachedCallArgumentAuditToolchainIdentity: ScriptValue?

    /// The call-audit contract is stricter than the legacy shared resolver: callers must
    /// provide exactly one selector, and a present selector must have the right JSON type.
    private static func resolveCallArgumentAuditFunction(
        _ arguments: ScriptValue,
        in functions: [FunctionSummary]
    ) throws -> FunctionSummary {
        let hasFunction = arguments["function"] != nil
        let hasAddress = arguments["address"] != nil
        guard hasFunction != hasAddress else {
            if hasFunction {
                throw ScriptingError.invalidArgument(
                    "function and address are mutually exclusive"
                )
            }
            throw ScriptingError.missingArgument("function or address")
        }
        // ★ Insight
        //
        // Local/static symbols can legitimately duplicate a name, and malformed or
        // synthetic analysis snapshots can contain overlapping ranges. Picking the
        // first match would make audit identity depend on array order. An exact start
        // does not outrank another containing range: the frozen selector contract also
        // accepts interior addresses, so every matching range is equally relevant and
        // ambiguity must fail closed.
        if hasFunction {
            guard let name = arguments["function"]?.stringValue else {
                throw ScriptingError.invalidArgument("function must be a string")
            }
            let matches = functions.filter { $0.name == name }
            guard !matches.isEmpty else {
                throw ScriptingError.invalidArgument("no function named '\(name)'")
            }
            guard matches.count == 1 else {
                throw ScriptingError.invalidArgument(
                    "function selector '\(name)' is ambiguous (\(matches.count) matches)"
                )
            }
            return matches[0]
        }
        guard arguments["address"]?.addressValue != nil else {
            throw ScriptingError.invalidArgument("address must be an address")
        }
        let target = arguments["address"]!.addressValue!
        let matches = functions.filter { function in
            function.endAddress > function.startAddress
                ? target >= function.startAddress && target < function.endAddress
                : target == function.startAddress
        }
        guard !matches.isEmpty else {
            throw ScriptingError.invalidArgument("no function at that address")
        }
        guard matches.count == 1 else {
            let targetText = ScriptValue.hex(target).stringValue ?? "<invalid-address>"
            throw ScriptingError.invalidArgument(
                "address selector \(targetText) is ambiguous (\(matches.count) matches)"
            )
        }
        return matches[0]
    }

    private static func callArgumentAuditInteger(
        _ value: Int,
        field: String,
        minimum: Int = Int.min
    ) throws -> ScriptValue {
        guard value >= minimum, let exact = Int64(exactly: value) else {
            throw ScriptingError.invalidArgument("\(field) is outside the audit integer range")
        }
        return .int(exact)
    }

    private static func callArgumentAuditString(
        _ value: String,
        field: String,
        allowEmpty: Bool = false
    ) throws -> ScriptValue {
        guard (allowEmpty || !value.isEmpty),
              !value.unicodeScalars.contains(where: { scalar in
                  if scalar.value == 0x2028 || scalar.value == 0x2029 { return true }
                  switch scalar.properties.generalCategory {
                  case .control, .format, .surrogate, .privateUse, .unassigned:
                      return true
                  default:
                      return false
                  }
              }) else {
            throw ScriptingError.invalidArgument("\(field) is not a canonical audit string")
        }
        return .string(value)
    }

    private static func isCanonicalAuditValueRegister(_ name: String) -> Bool {
        if ["sp", "wsp", "xzr", "wzr"].contains(name) { return true }
        guard let prefix = name.first,
              let index = Int(name.dropFirst()),
              String(index) == String(name.dropFirst()) else {
            return false
        }
        switch prefix {
        case "x", "w": return (0...30).contains(index)
        case "s", "d", "q", "v": return (0...31).contains(index)
        default: return false
        }
    }

    /// Structural identity only: selector substitutions and every other printer-only
    /// projection are deliberately excluded. Root depth is zero; nodes at depth 32 are
    /// accepted, while attempting to serialize any child at depth 33 fails closed.
    static func callArgumentAuditValueObject(
        _ value: MacIRValue,
        depth: Int = 0
    ) throws -> ScriptValue {
        guard depth <= 32 else {
            throw ScriptingError.invalidArgument(
                "call argument value exceeds the structural recursion limit"
            )
        }
        switch value {
        case let .register(name, version):
            guard isCanonicalAuditValueRegister(name), version >= 0 else {
                throw ScriptingError.invalidArgument("call argument register identity is invalid")
            }
            return .object([
                "kind": .string("register"),
                "name": .string(name),
                "version": try callArgumentAuditInteger(
                    version, field: "value_identity.version", minimum: 0
                ),
            ])
        case let .argument(bindingID):
            let bindingKind = switch bindingID.kind {
            case .gpr: "gpr"
            case .simd: "simd"
            case .entryStack: "entry-stack"
            }
            return .object([
                "kind": .string("argument"),
                "binding_kind": .string(bindingKind),
                "binding_value": try callArgumentAuditInteger(
                    bindingID.value, field: "value_identity.binding_value", minimum: 0
                ),
            ])
        case let .argumentFragment(rowID, offset, size):
            return .object([
                "kind": .string("argument-fragment"),
                "source_row": try callArgumentAuditString(rowID.rawValue, field: "value_identity.source_row"),
                "byte_offset": try callArgumentAuditInteger(offset, field: "value_identity.byte_offset", minimum: 0),
                "size": try callArgumentAuditInteger(size, field: "value_identity.size", minimum: 1),
            ])
        case let .abiComposite(type, fragments):
            guard (1...4).contains(fragments.count) else {
                throw ScriptingError.invalidArgument("aggregate fragment count is outside 1...4")
            }
            return .object([
                "kind": .string("abi-composite"),
                "type": try callArgumentAuditString(type, field: "value_identity.type"),
                "fragments": .array(try fragments.map {
                    try callArgumentAuditValueObject($0, depth: depth + 1)
                }),
            ])
        case let .immediate(immediate):
            return .object(["kind": .string("immediate"), "value": .int(immediate)])
        case let .stackSlot(offset):
            return .object(["kind": .string("stack-slot"), "offset": .int(offset)])
        case let .symbol(name):
            return .object([
                "kind": .string("symbol"),
                "name": try callArgumentAuditString(name, field: "value_identity.name"),
            ])
        case let .temporary(index):
            return .object([
                "kind": .string("temporary"),
                "index": try callArgumentAuditInteger(
                    index, field: "value_identity.index", minimum: 0
                ),
            ])
        case let .bitTest(nested, bit):
            guard (0...127).contains(bit) else {
                throw ScriptingError.invalidArgument("value_identity.bit is outside 0...127")
            }
            return .object([
                "kind": .string("bit-test"),
                "value": try callArgumentAuditValueObject(nested, depth: depth + 1),
                "bit": .int(bit),
            ])
        case let .unary(op, nested):
            return .object([
                "kind": .string("unary"),
                "operator": try callArgumentAuditString(op, field: "value_identity.operator"),
                "value": try callArgumentAuditValueObject(nested, depth: depth + 1),
            ])
        case let .binaryExpression(op, left, right):
            return .object([
                "kind": .string("binary"),
                "operator": try callArgumentAuditString(op, field: "value_identity.operator"),
                "left": try callArgumentAuditValueObject(left, depth: depth + 1),
                "right": try callArgumentAuditValueObject(right, depth: depth + 1),
            ])
        case let .signedBitfield(field):
            return .object([
                "kind": .string("signed-bitfield"),
                "source": try callArgumentAuditValueObject(field.source, depth: depth + 1),
                "operand_bits": .int(Int64(field.operandBits)),
                "source_lsb": .int(field.sourceLSB),
                "field_bits": .int(field.fieldBits),
                "insert_lsb": .int(field.insertLSB),
                "origin": .object([
                    "function_name": .string(field.origin.functionName),
                    "function_start": .string(String(field.origin.functionStart, radix: 16)),
                    "instruction_address": .string(String(field.origin.instructionAddress, radix: 16)),
                    "mnemonic": .string(field.origin.mnemonic),
                    "source_register": .string(field.origin.sourceRegister),
                    "destination_register": .string(field.origin.destinationRegister),
                    "definition": try callArgumentAuditValueObject(field.origin.definition, depth: depth + 2),
                    "definition_bits": .int(Int64(field.origin.definitionBits)),
                ]),
            ])
        case let .unknown(text):
            return .object([
                "kind": .string("unknown"),
                "text": try callArgumentAuditString(
                    text, field: "value_identity.text", allowEmpty: true
                ),
            ])
        }
    }

    private static func callArgumentAuditLocationObject(
        _ location: MacIRCallArgumentLocation
    ) throws -> ScriptValue {
        switch location {
        case let .gpr(index, carrierWidth):
            guard (0..<8).contains(index), carrierWidth == 32 || carrierWidth == 64 else {
                throw ScriptingError.invalidArgument("call argument GPR location is invalid")
            }
            return .object([
                "kind": .string("gpr"),
                "index": .int(Int64(index)),
                "carrier_width": .int(Int64(carrierWidth)),
                "scalar_width": .null,
                "byte_offset": .null,
                "size": .null,
                "alignment": .null,
            ])
        case let .simd(index, scalarWidth):
            guard (0..<8).contains(index), scalarWidth == 32 || scalarWidth == 64 else {
                throw ScriptingError.invalidArgument("call argument SIMD location is invalid")
            }
            return .object([
                "kind": .string("simd"),
                "index": .int(Int64(index)),
                "carrier_width": .null,
                "scalar_width": .int(Int64(scalarWidth)),
                "byte_offset": .null,
                "size": .null,
                "alignment": .null,
            ])
        case let .callStack(byteOffset, size, alignment):
            let (end, overflow) = byteOffset.addingReportingOverflow(size)
            guard byteOffset >= 0, size > 0, alignment > 0,
                  alignment.nonzeroBitCount == 1, byteOffset.isMultiple(of: alignment),
                  !overflow, end > byteOffset else {
                throw ScriptingError.invalidArgument("call argument stack location is invalid")
            }
            return .object([
                "kind": .string("call-stack"),
                "index": .null,
                "carrier_width": .null,
                "scalar_width": .null,
                "byte_offset": try callArgumentAuditInteger(
                    byteOffset, field: "location.byte_offset", minimum: 0
                ),
                "size": try callArgumentAuditInteger(size, field: "location.size", minimum: 1),
                "alignment": try callArgumentAuditInteger(
                    alignment, field: "location.alignment", minimum: 1
                ),
            ])
        }
    }

    private static func callArgumentAuditObservationObject(
        _ scope: MacIRCallArgumentObservationScope
    ) throws -> ScriptValue {
        .object([
            "gpr_indices": .array(scope.canonicalGPRIndicesForAudit.map {
                .int(Int64($0))
            }),
            "scalar_simd_indices": .array(scope.canonicalScalarSIMDIndicesForAudit.map {
                .int(Int64($0))
            }),
            "call_stack_ranges": .array(try scope.canonicalCallStackRangesForAudit.map { range in
                .object([
                    "start": try callArgumentAuditInteger(
                        range.lowerBound, field: "observation.call_stack_ranges.start", minimum: 0
                    ),
                    "end": try callArgumentAuditInteger(
                        range.upperBound, field: "observation.call_stack_ranges.end", minimum: 1
                    ),
                ])
            }),
        ])
    }

    private static func isConservativeAuditSelectorIdentifier(_ selector: String) -> Bool {
        guard let first = selector.utf8.first,
              first == 0x5f || (0x41...0x5a).contains(first) || (0x61...0x7a).contains(first) else {
            return false
        }
        return selector.utf8.dropFirst().allSatisfy { byte in
            byte == 0x5f
                || (0x41...0x5a).contains(byte)
                || (0x61...0x7a).contains(byte)
                || (0x30...0x39).contains(byte)
        }
    }

    /// ★ Insight
    ///
    /// A rendered call line may repeat `_objc_msgSend(...)` in its diagnostic comment even
    /// when the executable statement is a valid bracket message. Match only the statement
    /// before its one top-level semicolon, using the same conservative grammar as the frozen
    /// Python producer/comparator.
    static func isExactZeroSelectorMessageForAudit(
        _ renderedLine: String,
        selector: String
    ) -> Bool {
        guard isConservativeAuditSelectorIdentifier(selector),
              !renderedLine.contains("\r"), !renderedLine.contains("\n") else {
            return false
        }
        var inString = false
        var escaped = false
        var depth = 0
        var semicolon: String.Index?
        statementScan: for index in renderedLine.indices {
            let character = renderedLine[index]
            if inString {
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == "\"" {
                    inString = false
                }
                continue
            }
            switch character {
            case "\"":
                inString = true
            case "(", "[":
                depth += 1
            case ")", "]":
                depth -= 1
                if depth < 0 { return false }
            case ";" where depth == 0:
                semicolon = index
                break statementScan
            default:
                break
            }
        }
        guard let semicolon else { return false }
        let body = String(renderedLine[..<semicolon])
            .trimmingCharacters(in: .whitespaces)
        let suffix = String(renderedLine[renderedLine.index(after: semicolon)...])
        guard suffix.isEmpty || suffix.hasPrefix(" //"),
              body.hasSuffix("]"),
              let openBracket = body.firstIndex(of: "[") else {
            return false
        }
        let prefix = String(body[..<openBracket])
            .trimmingCharacters(in: .whitespaces)
        guard prefix.isEmpty || prefix == "return" || prefix.hasSuffix("=") else {
            return false
        }
        let closingBracket = body.index(before: body.endIndex)
        var bracketDepth = 0
        inString = false
        escaped = false
        for index in body[openBracket...].indices {
            let character = body[index]
            if inString {
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == "\"" {
                    inString = false
                }
                continue
            }
            switch character {
            case "\"":
                inString = true
            case "[":
                bracketDepth += 1
            case "]":
                bracketDepth -= 1
                if bracketDepth < 0 || (bracketDepth == 0 && index != closingBracket) {
                    return false
                }
            default:
                break
            }
        }
        guard !inString, bracketDepth == 0 else { return false }
        let contentStart = body.index(after: openBracket)
        let content = String(body[contentStart..<closingBracket])
        let marker = " \(selector)"
        guard content.hasSuffix(marker) else { return false }
        return !content.dropLast(marker.count)
            .trimmingCharacters(in: .whitespaces)
            .isEmpty
    }

    nonisolated static func machineCallArgumentAuditClassifications(
        frame: MacIRCallFrame
    ) -> [MacIRCallArgumentPhysicalKey: (included: Bool, reason: String)]? {
        guard frame.knownSignature == nil, let rendered = frame.machineRenderArguments else { return nil }
        let keys = Set(rendered.compactMap { $0.location.physicalKey })
        var result: [MacIRCallArgumentPhysicalKey: (included: Bool, reason: String)] = [:]
        for argument in frame.arguments.canonicalPhysicalEntriesForAudit {
            guard argument.role == .unknown, let key = argument.location.physicalKey else { return nil }
            result[key] = keys.contains(key)
                ? (true, "machine-register-input") : (false, "unknown-gap")
        }
        return result
    }

    private static func callArgumentAuditSafeClassifications(
        frame: MacIRCallFrame,
        renderedLine: String
    ) throws -> [MacIRCallArgumentPhysicalKey: CallArgumentSafeRenderClassification] {
        let arguments = frame.arguments.canonicalPhysicalEntriesForAudit
        var result: [MacIRCallArgumentPhysicalKey: CallArgumentSafeRenderClassification] = [:]
        if frame.knownSignature != nil {
            var fixedPositions: Set<Int> = []
            let formatTailRenders: Bool = {
                guard case .formatString = frame.tailCountEvidence else { return false }
                return frame.completeKnownVariadicRenderValues() != nil
            }()
            for argument in arguments {
                if case let .anonymousVariadic(tailOrdinal) = argument.role,
                   case .formatString = frame.tailCountEvidence,
                   tailOrdinal >= 0,
                   let key = argument.location.physicalKey {
                    // HOP-5c: a format-string tail renders exactly when the frame is complete.
                    result[key] = CallArgumentSafeRenderClassification(
                        included: formatTailRenders,
                        reason: formatTailRenders ? "format-string-tail" : "format-string-tail-gap"
                    )
                    continue
                }
                guard case let .fixed(sourcePosition) = argument.role,
                      sourcePosition >= 0 else {
                    throw ScriptingError.invalidArgument(
                        "known call contains a non-fixed Phase-A argument"
                    )
                }
                fixedPositions.insert(sourcePosition)
            }
            var denseFixedCount = 0
            while fixedPositions.contains(denseFixedCount) { denseFixedCount += 1 }

            let selectorRows = arguments.filter { $0.selectorEvidence != nil }
            var completeZeroMessage = false
            if frame.expectedTailCount == 0,
               selectorRows.count == 1,
               let selector = selectorRows[0].selectorEvidence,
               selectorRows[0].location == .gpr(index: 1, carrierWidth: 64),
               selectorRows[0].role == .fixed(sourcePosition: 1),
               fixedPositions == Set([0, 1]),
               isConservativeAuditSelectorIdentifier(selector.name) {
                guard isExactZeroSelectorMessageForAudit(renderedLine, selector: selector.name) else {
                    throw ScriptingError.invalidArgument(
                        "zero-tail Objective-C call did not render as its bracket message"
                    )
                }
                completeZeroMessage = true
            }
            for argument in arguments where argument.tailOrdinal == nil {
                guard let key = argument.location.physicalKey,
                      let position = argument.sourcePosition else {
                    throw ScriptingError.invalidArgument("known call argument lacks a physical key")
                }
                result[key] = if completeZeroMessage {
                    CallArgumentSafeRenderClassification(
                        included: true, reason: "objc-complete-message"
                    )
                } else if position < denseFixedCount {
                    CallArgumentSafeRenderClassification(included: true, reason: "fixed-prefix")
                } else {
                    CallArgumentSafeRenderClassification(included: false, reason: "fixed-gap")
                }
            }
            return result
        }

        if let machine = machineCallArgumentAuditClassifications(frame: frame) {
            return machine.mapValues {
                CallArgumentSafeRenderClassification(included: $0.included, reason: $0.reason)
            }
        }

        let observation = frame.arguments.observationScope
        let observedGPRs = Set(observation.canonicalGPRIndicesForAudit)
        let argumentGPRs = Set(arguments.compactMap { argument -> Int? in
            guard case let .gpr(index, _) = argument.location else { return nil }
            return index
        })
        let allArgumentsAreGPR = arguments.allSatisfy {
            if case .gpr = $0.location { return true }
            return false
        }
        let hasObservedSIMD = !observation.canonicalScalarSIMDIndicesForAudit.isEmpty
        let hasObservedStack = !observation.canonicalCallStackRangesForAudit.isEmpty
        let canRenderPrefix = allArgumentsAreGPR
            && !hasObservedSIMD
            && !hasObservedStack
            && observedGPRs.contains(0)
        var denseUnknownCount = 0
        if canRenderPrefix {
            while observedGPRs.contains(denseUnknownCount)
                    && argumentGPRs.contains(denseUnknownCount) {
                denseUnknownCount += 1
            }
        }
        for argument in arguments {
            guard argument.role == .unknown, let key = argument.location.physicalKey else {
                throw ScriptingError.invalidArgument(
                    "unknown call contains a non-unknown or invalid argument"
                )
            }
            let classification: CallArgumentSafeRenderClassification
            if canRenderPrefix,
               case let .gpr(index, _) = argument.location,
               index < denseUnknownCount {
                classification = CallArgumentSafeRenderClassification(
                    included: true, reason: "unknown-gpr-prefix"
                )
            } else if case .callStack = argument.location {
                classification = CallArgumentSafeRenderClassification(
                    included: false, reason: "unproven-stack"
                )
            } else if hasObservedStack {
                classification = CallArgumentSafeRenderClassification(
                    included: false, reason: "unproven-stack"
                )
            } else if case .simd = argument.location {
                classification = CallArgumentSafeRenderClassification(
                    included: false, reason: "unproven-bank-order"
                )
            } else if hasObservedSIMD {
                classification = CallArgumentSafeRenderClassification(
                    included: false, reason: "unproven-bank-order"
                )
            } else {
                classification = CallArgumentSafeRenderClassification(
                    included: false, reason: "unknown-gap"
                )
            }
            result[key] = classification
        }
        return result
    }

    private static func callArgumentAuditArgumentObject(
        _ argument: MacIRCallArgument,
        classification: CallArgumentSafeRenderClassification
    ) throws -> ScriptValue {
        let role: String
        let sourcePosition: ScriptValue
        let tailOrdinal: ScriptValue
        switch argument.role {
        case let .fixed(position):
            role = "fixed"
            sourcePosition = try callArgumentAuditInteger(
                position, field: "argument.source_position", minimum: 0
            )
            tailOrdinal = .null
        case let .anonymousVariadic(ordinal):
            // HOP-5c: only format-string tails pass frame validation.
            role = "anonymous-variadic"
            sourcePosition = .null
            tailOrdinal = try callArgumentAuditInteger(
                ordinal, field: "argument.tail_ordinal", minimum: 0
            )
        case .unknown:
            role = "unknown"
            sourcePosition = .null
            tailOrdinal = .null
        }
        let selectorName: ScriptValue
        let selectorAddress: ScriptValue
        if let selector = argument.selectorEvidence {
            selectorName = try callArgumentAuditString(
                selector.name, field: "argument.selector_name"
            )
            selectorAddress = .hex(selector.selrefAddress)
        } else {
            selectorName = .null
            selectorAddress = .null
        }
        return .object([
            "location": try callArgumentAuditLocationObject(argument.location),
            "role": .string(role),
            "source_position": sourcePosition,
            "tail_ordinal": tailOrdinal,
            "value_identity": try callArgumentAuditValueObject(argument.value),
            "selector_name": selectorName,
            "selector_selref_address": selectorAddress,
            "safe_render_included": .bool(classification.included),
            "safe_render_reason": .string(classification.reason),
        ])
    }

    private static func callArgumentAuditControlObject(
        _ control: MacIRCallControlInput
    ) throws -> ScriptValue {
        let role = switch control.role {
        case .indirectTarget: "indirect-target"
        case .pointerAuthenticationModifier: "pointer-authentication-modifier"
        }
        guard let register = control.register.registerName else {
            throw ScriptingError.invalidArgument("call control register is invalid")
        }
        return .object([
            "role": .string(role),
            "register": .string(register),
            "value_identity": try callArgumentAuditValueObject(control.value),
        ])
    }

    private static func callArgumentAuditTailObject(
        _ evidence: MacIRCallTailCountEvidence?
    ) throws -> ScriptValue {
        guard let evidence else { return .null }
        switch evidence {
        case let .objectiveCSelectorColonCount(count):
            return .object([
                "kind": .string("objective-c-selector-colon-count"),
                "expected_tail_count": try callArgumentAuditInteger(
                    count, field: "tail_count_evidence.expected_tail_count", minimum: 0
                ),
            ])
        case let .formatString(format):
            return .object([
                "kind": .string("format-string"),
                "provenance": .string(MacIRCallFormatStringEvidence.provenance),
                "format_attribute_kind": try callArgumentAuditString(
                    format.kind, field: "tail_count_evidence.format_attribute_kind"
                ),
                "format_address": .hex(format.formatAddress),
                "expected_tail_count": try callArgumentAuditInteger(
                    format.argumentTypes.count,
                    field: "tail_count_evidence.expected_tail_count",
                    minimum: 0
                ),
            ])
        }
    }

    struct CallArgumentAuditFileFingerprint: Equatable {
        let canonicalPath: String
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let changeSeconds: Int64
        let changeNanoseconds: Int64
        let sha256: String
    }

    struct CallArgumentAuditRenderedBinding: Equatable {
        let line: PseudocodeLine
        let occurrence: Int
        let utf8SHA256: String
    }

    typealias CallArgumentAuditToolRunner = (
        _ executableURL: URL,
        _ arguments: [String],
        _ environment: [String: String],
        _ timeout: TimeInterval
    ) throws -> String

    private struct CallArgumentAuditFileIdentity: Equatable {
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let changeSeconds: Int64
        let changeNanoseconds: Int64
    }

    private struct CallArgumentAuditProcessStreamCapture: Sendable {
        let data: Data
        let overflowed: Bool
        let readError: Int32?
        let cancelled: Bool
    }

    private final class CallArgumentAuditProcessCapture: @unchecked Sendable {
        private let lock = NSLock()
        private var stdout: CallArgumentAuditProcessStreamCapture?
        private var stderr: CallArgumentAuditProcessStreamCapture?
        private var cancellationRequested = false

        func setStdout(_ capture: CallArgumentAuditProcessStreamCapture) {
            lock.lock()
            stdout = capture
            lock.unlock()
        }

        func setStderr(_ capture: CallArgumentAuditProcessStreamCapture) {
            lock.lock()
            stderr = capture
            lock.unlock()
        }

        func requestCancellation() {
            lock.lock()
            cancellationRequested = true
            lock.unlock()
        }

        func isCancellationRequested() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return cancellationRequested
        }

        func snapshot() -> (
            stdout: CallArgumentAuditProcessStreamCapture?,
            stderr: CallArgumentAuditProcessStreamCapture?
        ) {
            lock.lock()
            defer { lock.unlock() }
            return (stdout, stderr)
        }
    }

    nonisolated static let callArgumentAuditProcessOutputLimit = 64 * 1_024
    nonisolated private static let callArgumentAuditProcessReadChunkSize = 16 * 1_024
    nonisolated private static let callArgumentAuditProcessPollMilliseconds: Int32 = 20

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    nonisolated private static func callArgumentAuditFileIdentity(
        _ value: stat
    ) -> CallArgumentAuditFileIdentity {
        CallArgumentAuditFileIdentity(
            device: UInt64(value.st_dev),
            inode: UInt64(value.st_ino),
            size: Int64(value.st_size),
            modificationSeconds: Int64(value.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(value.st_mtimespec.tv_nsec),
            changeSeconds: Int64(value.st_ctimespec.tv_sec),
            changeNanoseconds: Int64(value.st_ctimespec.tv_nsec)
        )
    }

    nonisolated static let callArgumentAuditFileReadChunkSize = 1 * 1_024 * 1_024

    /// ★ Insight ─────────────────────────────────────
    /// Whole-file provenance does not require whole-file residency. Hash exactly the
    /// descriptor-bound `st_size` in fixed chunks, then require immediate EOF; this
    /// bounds memory while making both concurrent truncation and append fail closed.
    /// The outer path/descriptor identity recheck still detects replacement or edits
    /// that occur after the EOF probe.
    /// ─────────────────────────────────────────────────
    nonisolated static func callArgumentAuditDescriptorDigest(
        descriptor: Int32,
        expectedSize: Int64,
        chunkSize: Int = callArgumentAuditFileReadChunkSize,
        afterChunk: ((Int64) throws -> Void)? = nil
    ) throws -> String {
        guard expectedSize >= 0, chunkSize > 0,
              chunkSize <= callArgumentAuditFileReadChunkSize else {
            throw ScriptingError.invalidArgument("invalid audit file digest bounds")
        }
        var hasher = SHA256()
        var totalRead: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        while totalRead < expectedSize {
            let requestCount = min(chunkSize, Int(expectedSize - totalRead))
            let byteCount = buffer.withUnsafeMutableBytes { storage in
                Darwin.read(descriptor, storage.baseAddress, requestCount)
            }
            if byteCount < 0 {
                if errno == EINTR { continue }
                let diagnostic = String(cString: strerror(errno))
                throw ScriptingError.invalidArgument(
                    "cannot read complete audit file: \(diagnostic)"
                )
            }
            guard byteCount > 0 else {
                throw ScriptingError.invalidArgument(
                    "audit file changed size while it was fingerprinted"
                )
            }
            hasher.update(data: Data(buffer.prefix(byteCount)))
            totalRead += Int64(byteCount)
            try afterChunk?(totalRead)
        }

        var extraByte: UInt8 = 0
        while true {
            let extraCount = Darwin.read(descriptor, &extraByte, 1)
            if extraCount < 0, errno == EINTR { continue }
            if extraCount < 0 {
                let diagnostic = String(cString: strerror(errno))
                throw ScriptingError.invalidArgument(
                    "cannot finish reading audit file: \(diagnostic)"
                )
            }
            guard extraCount == 0 else {
                throw ScriptingError.invalidArgument(
                    "audit file changed size while it was fingerprinted"
                )
            }
            break
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    nonisolated static func callArgumentAuditFileFingerprint(
        at originalURL: URL
    ) throws -> CallArgumentAuditFileFingerprint {
        let standardized = originalURL.standardizedFileURL
        guard standardized.path.hasPrefix("/") else {
            throw ScriptingError.invalidArgument("audit file path must be absolute")
        }
        let canonical = standardized.resolvingSymlinksInPath().standardizedFileURL
        var pathBefore = stat()
        guard stat(canonical.path, &pathBefore) == 0 else {
            let diagnostic = String(cString: strerror(errno))
            throw ScriptingError.invalidArgument("cannot stat audit file: \(diagnostic)")
        }
        guard pathBefore.st_mode & S_IFMT == S_IFREG else {
            throw ScriptingError.invalidArgument("audit file is not a canonical regular file")
        }

        let descriptor = open(canonical.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else {
            let diagnostic = String(cString: strerror(errno))
            throw ScriptingError.invalidArgument("cannot open audit file: \(diagnostic)")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }

        var descriptorBefore = stat()
        guard fstat(descriptor, &descriptorBefore) == 0,
              descriptorBefore.st_mode & S_IFMT == S_IFREG else {
            throw ScriptingError.invalidArgument("cannot bind audit file descriptor metadata")
        }
        let initialIdentity = callArgumentAuditFileIdentity(pathBefore)
        guard callArgumentAuditFileIdentity(descriptorBefore) == initialIdentity,
              initialIdentity.size >= 0 else {
            throw ScriptingError.invalidArgument("audit file changed while it was opened")
        }

        // Whole-file hashing is the audit's longest synchronous phase; observe the
        // owning request's cancellation once per bounded chunk. Outside a task this is a no-op.
        let digest = try callArgumentAuditDescriptorDigest(
            descriptor: descriptor, expectedSize: initialIdentity.size,
            afterChunk: { _ in try Task.checkCancellation() }
        )

        var descriptorAfter = stat()
        var pathAfter = stat()
        guard fstat(descriptor, &descriptorAfter) == 0,
              stat(canonical.path, &pathAfter) == 0,
              callArgumentAuditFileIdentity(descriptorAfter) == initialIdentity,
              callArgumentAuditFileIdentity(pathAfter) == initialIdentity else {
            throw ScriptingError.invalidArgument(
                "audit file metadata or content changed while it was fingerprinted"
            )
        }
        return CallArgumentAuditFileFingerprint(
            canonicalPath: canonical.path,
            device: initialIdentity.device,
            inode: initialIdentity.inode,
            size: initialIdentity.size,
            modificationSeconds: initialIdentity.modificationSeconds,
            modificationNanoseconds: initialIdentity.modificationNanoseconds,
            changeSeconds: initialIdentity.changeSeconds,
            changeNanoseconds: initialIdentity.changeNanoseconds,
            sha256: digest
        )
    }

    private static func runningExecutableURL() throws -> URL {
        var capacity: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &capacity)
        guard capacity > 0 else {
            throw ScriptingError.invalidArgument("cannot resolve the running executable path")
        }
        var buffer = [CChar](repeating: 0, count: Int(capacity))
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            _NSGetExecutablePath(pointer.baseAddress, &capacity)
        }
        guard status == 0 else {
            throw ScriptingError.invalidArgument("cannot resolve the running executable path")
        }
        let path = buffer.withUnsafeBufferPointer { pointer in
            String(cString: pointer.baseAddress!)
        }
        return URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL
    }

    private static func configureCallArgumentAuditProcessPipe(
        descriptor: Int32,
        label: String
    ) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            let diagnostic = String(cString: strerror(errno))
            throw ScriptingError.invalidArgument(
                "cannot configure audit child \(label) pipe: \(diagnostic)"
            )
        }
    }

    /// ★ Insight ─────────────────────────────────────
    /// A timeout cannot cancel a blocking pipe `read`, and bounding only the retained
    /// `Data` still lets an overflowing child deadlock on a full pipe. Nonblocking
    /// chunk reads let both workers keep draining/discarding after the evidence cap,
    /// while a short poll interval makes cancellation deterministic on every exit path.
    /// ─────────────────────────────────────────────────
    nonisolated private static func drainCallArgumentAuditProcessStream(
        descriptor: Int32,
        capture: CallArgumentAuditProcessCapture
    ) -> CallArgumentAuditProcessStreamCapture {
        var retained = Data()
        retained.reserveCapacity(callArgumentAuditProcessOutputLimit)
        var overflowed = false
        var buffer = [UInt8](repeating: 0, count: callArgumentAuditProcessReadChunkSize)

        while !capture.isCancellationRequested() {
            let byteCount = buffer.withUnsafeMutableBytes { storage in
                Darwin.read(descriptor, storage.baseAddress, storage.count)
            }
            if byteCount > 0 {
                let remaining = max(0, callArgumentAuditProcessOutputLimit - retained.count)
                let retainedCount = min(byteCount, remaining)
                if retainedCount > 0 {
                    retained.append(contentsOf: buffer.prefix(retainedCount))
                }
                if byteCount > retainedCount { overflowed = true }
                continue
            }
            if byteCount == 0 {
                return CallArgumentAuditProcessStreamCapture(
                    data: retained, overflowed: overflowed, readError: nil, cancelled: false
                )
            }

            let readError = errno
            if readError == EINTR { continue }
            if readError != EAGAIN && readError != EWOULDBLOCK {
                return CallArgumentAuditProcessStreamCapture(
                    data: retained, overflowed: overflowed,
                    readError: readError, cancelled: false
                )
            }

            var event = pollfd(
                fd: descriptor,
                events: Int16(POLLIN | POLLHUP | POLLERR),
                revents: 0
            )
            let pollStatus = Darwin.poll(
                &event, 1, callArgumentAuditProcessPollMilliseconds
            )
            if pollStatus < 0, errno != EINTR {
                return CallArgumentAuditProcessStreamCapture(
                    data: retained, overflowed: overflowed,
                    readError: errno, cancelled: false
                )
            }
        }

        return CallArgumentAuditProcessStreamCapture(
            data: retained, overflowed: overflowed, readError: nil, cancelled: true
        )
    }

    static func runCallArgumentAuditProcess(
        executableURL: URL,
        arguments: [String],
        environment: [String: String],
        timeout: TimeInterval
    ) throws -> String {
        guard timeout > 0, timeout.isFinite else {
            throw ScriptingError.invalidArgument("audit child timeout must be positive and finite")
        }
        try Task.checkCancellation()
        let process = Process()
        let standardOutput = Pipe()
        let standardError = Pipe()
        let stdoutHandle = standardOutput.fileHandleForReading
        let stderrHandle = standardError.fileHandleForReading
        defer {
            try? stdoutHandle.close()
            try? stderrHandle.close()
        }
        try configureCallArgumentAuditProcessPipe(
            descriptor: stdoutHandle.fileDescriptor, label: "stdout"
        )
        try configureCallArgumentAuditProcessPipe(
            descriptor: stderrHandle.fileDescriptor, label: "stderr"
        )
        process.executableURL = executableURL
        process.arguments = arguments
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = standardOutput
        process.standardError = standardError
        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        try Task.checkCancellation()
        do {
            try process.run()
        } catch {
            throw ScriptingError.invalidArgument(
                "cannot launch audit child \(executableURL.path): \(error.localizedDescription)"
            )
        }

        let capture = CallArgumentAuditProcessCapture()
        let drains = DispatchGroup()
        drains.enter()
        DispatchQueue.global(qos: .userInteractive).async {
            defer { drains.leave() }
            capture.setStdout(drainCallArgumentAuditProcessStream(
                descriptor: stdoutHandle.fileDescriptor, capture: capture
            ))
        }
        drains.enter()
        DispatchQueue.global(qos: .userInteractive).async {
            defer { drains.leave() }
            capture.setStderr(drainCallArgumentAuditProcessStream(
                descriptor: stderrHandle.fileDescriptor, capture: capture
            ))
        }

        let deadline = DispatchTime.now() + timeout
        var cancelled = false
        var terminatedInTime = false
        while DispatchTime.now() < deadline {
            if Task.isCancelled { cancelled = true; break }
            if terminated.wait(timeout: min(deadline, .now() + 0.025)) == .success {
                terminatedInTime = true
                break
            }
        }
        if !terminatedInTime {
            let ownedPID = process.processIdentifier
            if process.isRunning { process.terminate() }
            if terminated.wait(timeout: .now() + 0.25) == .timedOut,
               process.isRunning {
                let killStatus = kill(ownedPID, SIGKILL)
                let killError = errno
                if killStatus != 0, killError != ESRCH {
                    process.terminate()
                }
                process.waitUntilExit()
            }
            if process.isRunning {
                process.waitUntilExit()
            }
            capture.requestCancellation()
            drains.wait()
            process.terminationHandler = nil
            if cancelled { throw CancellationError() }
            throw ScriptingError.invalidArgument(
                "audit child \(executableURL.lastPathComponent) exceeded \(timeout) seconds"
            )
        }
        let drainDeadline = DispatchTime.now() + 1
        var drained = false
        while DispatchTime.now() < drainDeadline {
            if Task.isCancelled {
                capture.requestCancellation()
                drains.wait()
                process.terminationHandler = nil
                throw CancellationError()
            }
            if drains.wait(timeout: min(drainDeadline, .now() + 0.025)) == .success {
                drained = true
                break
            }
        }
        if !drained {
            capture.requestCancellation()
            drains.wait()
            process.terminationHandler = nil
            throw ScriptingError.invalidArgument(
                "audit child \(executableURL.lastPathComponent) output drain timed out"
            )
        }
        process.terminationHandler = nil
        let captured = capture.snapshot()
        guard let stdoutCapture = captured.stdout, let stderrCapture = captured.stderr else {
            throw ScriptingError.invalidArgument("audit child output capture was incomplete")
        }
        for (label, stream) in [("stdout", stdoutCapture), ("stderr", stderrCapture)] {
            if stream.cancelled {
                throw ScriptingError.invalidArgument("audit child \(label) capture was cancelled")
            }
            if let readError = stream.readError {
                throw ScriptingError.invalidArgument(
                    "audit child \(label) read failed: \(String(cString: strerror(readError)))"
                )
            }
            if stream.overflowed {
                throw ScriptingError.invalidArgument(
                    "audit child \(label) exceeded \(callArgumentAuditProcessOutputLimit) bytes"
                )
            }
        }
        guard let stdout = String(data: stdoutCapture.data, encoding: .utf8) else {
            throw ScriptingError.invalidArgument("audit child stdout is not valid UTF-8")
        }
        guard let stderr = String(data: stderrCapture.data, encoding: .utf8) else {
            throw ScriptingError.invalidArgument("audit child stderr is not valid UTF-8")
        }
        guard process.terminationStatus == 0 else {
            let diagnostic = stderr.split(whereSeparator: \.isNewline).first.map(String.init)
                ?? "exit \(process.terminationStatus)"
            throw ScriptingError.invalidArgument(
                "audit child \(executableURL.lastPathComponent) failed: \(diagnostic)"
            )
        }
        return stdout
    }

    private static func exactCallArgumentAuditToolLines(
        _ output: String,
        label: String
    ) throws -> [String] {
        let lines = output.split(whereSeparator: \.isNewline)
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !lines.isEmpty else {
            throw ScriptingError.invalidArgument("active \(label) output is not normalized")
        }
        for line in lines {
            _ = try callArgumentAuditString(line, field: "active \(label) output")
        }
        return lines
    }

    private static func canonicalCallArgumentAuditURL(
        _ rawPath: String,
        label: String,
        requireDirectory: Bool
    ) throws -> URL {
        _ = try callArgumentAuditString(rawPath, field: label)
        let standardized = URL(fileURLWithPath: rawPath).standardizedFileURL
        guard standardized.path.hasPrefix("/") else {
            throw ScriptingError.invalidArgument("\(label) must be absolute")
        }
        let canonical = standardized.resolvingSymlinksInPath().standardizedFileURL
        let values = try? canonical.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey])
        let valid = requireDirectory ? values?.isDirectory == true : values?.isRegularFile == true
        guard valid else {
            throw ScriptingError.invalidArgument("\(label) does not resolve to the expected file type")
        }
        return canonical
    }

    private static func callArgumentAuditURL(
        _ child: URL,
        isWithin directory: URL
    ) -> Bool {
        child.path == directory.path || child.path.hasPrefix(directory.path + "/")
    }

    static func sampleCallArgumentAuditToolchainIdentity(
        environment sourceEnvironment: [String: String],
        runner: CallArgumentAuditToolRunner
    ) throws -> ScriptValue {
        var environment = sourceEnvironment
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"
        environment["LANGUAGE"] = "C"
        let developerPath: String
        if let configured = environment["DEVELOPER_DIR"], !configured.isEmpty {
            developerPath = configured
        } else {
            let output = try runner(
                URL(fileURLWithPath: "/usr/bin/xcode-select"), ["-p"], environment, 10
            )
            let lines = try exactCallArgumentAuditToolLines(
                output, label: "developer directory"
            )
            guard lines.count == 1 else {
                throw ScriptingError.invalidArgument("active developer directory is ambiguous")
            }
            developerPath = lines[0]
        }
        let developerDirectory = try canonicalCallArgumentAuditURL(
            developerPath, label: "DEVELOPER_DIR", requireDirectory: true
        )
        environment["DEVELOPER_DIR"] = developerDirectory.path

        let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
        func xcrunOutput(_ arguments: [String]) throws -> String {
            try runner(xcrun, arguments, environment, 10)
        }
        func exactSingleLine(_ output: String, label: String) throws -> String {
            let lines = try exactCallArgumentAuditToolLines(output, label: label)
            guard lines.count == 1 else {
                throw ScriptingError.invalidArgument("active \(label) output is ambiguous")
            }
            return lines[0]
        }

        let xcodebuild = try canonicalCallArgumentAuditURL(
            exactSingleLine(
                try xcrunOutput(["--find", "xcodebuild"]), label: "xcodebuild path"
            ),
            label: "xcodebuild path",
            requireDirectory: false
        )
        let clang = try canonicalCallArgumentAuditURL(
            exactSingleLine(try xcrunOutput(["--find", "clang"]), label: "clang path"),
            label: "clang path",
            requireDirectory: false
        )
        let sdk = try canonicalCallArgumentAuditURL(
            exactSingleLine(
                try xcrunOutput(["--sdk", "macosx", "--show-sdk-path"]),
                label: "macOS SDK path"
            ),
            label: "macOS SDK path",
            requireDirectory: true
        )
        guard callArgumentAuditURL(xcodebuild, isWithin: developerDirectory),
              callArgumentAuditURL(clang, isWithin: developerDirectory),
              callArgumentAuditURL(sdk, isWithin: developerDirectory) else {
            throw ScriptingError.invalidArgument(
                "active Xcode, clang, and macOS SDK do not share one DEVELOPER_DIR"
            )
        }

        let xcodeLines = try exactCallArgumentAuditToolLines(
            try runner(xcodebuild, ["-version"], environment, 10),
            label: "Xcode version"
        )
        guard xcodeLines.count == 2,
              xcodeLines[0].hasPrefix("Xcode "),
              xcodeLines[1].hasPrefix("Build version ") else {
            throw ScriptingError.invalidArgument("active Xcode version output is malformed")
        }
        let xcodeVersion = String(xcodeLines[0].dropFirst("Xcode ".count))
        let xcodeBuild = String(xcodeLines[1].dropFirst("Build version ".count))
        let versionComponents = xcodeVersion.split(separator: ".", omittingEmptySubsequences: false)
        guard !versionComponents.isEmpty,
              versionComponents.allSatisfy({ component in
                  !component.isEmpty && component.utf8.allSatisfy({ (0x30...0x39).contains($0) })
              }),
              !xcodeBuild.isEmpty,
              xcodeBuild.utf8.allSatisfy({ byte in
                  (0x30...0x39).contains(byte)
                      || (0x41...0x5a).contains(byte)
                      || (0x61...0x7a).contains(byte)
              }) else {
            throw ScriptingError.invalidArgument("active Xcode version fields are malformed")
        }
        let sdkVersion = try exactSingleLine(
            try xcrunOutput(["--sdk", "macosx", "--show-sdk-version"]),
            label: "macOS SDK version"
        )
        let sdkVersionComponents = sdkVersion.split(
            separator: ".", omittingEmptySubsequences: false
        )
        guard !sdkVersionComponents.isEmpty,
              sdkVersionComponents.allSatisfy({ component in
                  !component.isEmpty && component.utf8.allSatisfy({ (0x30...0x39).contains($0) })
              }) else {
            throw ScriptingError.invalidArgument("active macOS SDK version is malformed")
        }
        let clangLines = try exactCallArgumentAuditToolLines(
            try runner(clang, ["--version"], environment, 10),
            label: "clang version"
        )
        guard let clangVersion = clangLines.first else {
            throw ScriptingError.invalidArgument("active clang version output is empty")
        }

        let xcodeVersionValue = try callArgumentAuditString(
            xcodeVersion, field: "toolchain_identity.xcode_version"
        )
        let xcodeBuildValue = try callArgumentAuditString(
            xcodeBuild, field: "toolchain_identity.xcode_build"
        )
        let sdkCanonicalValue = try callArgumentAuditString(
            "macosx\(sdkVersion)", field: "toolchain_identity.sdk_canonical_name"
        )
        let sdkVersionValue = try callArgumentAuditString(
            sdkVersion, field: "toolchain_identity.sdk_version"
        )
        let clangVersionValue = try callArgumentAuditString(
            clangVersion, field: "toolchain_identity.clang_version"
        )
        return .object([
            "xcode_version": xcodeVersionValue,
            "xcode_build": xcodeBuildValue,
            "sdk_canonical_name": sdkCanonicalValue,
            "sdk_version": sdkVersionValue,
            "clang_version": clangVersionValue,
        ])
    }

    private static func activeToolchainIdentityObject() throws -> ScriptValue {
        if let cachedCallArgumentAuditToolchainIdentity {
            return cachedCallArgumentAuditToolchainIdentity
        }
        let identity = try sampleCallArgumentAuditToolchainIdentity(
            environment: ProcessInfo.processInfo.environment
        ) { executableURL, arguments, environment, timeout in
            try runCallArgumentAuditProcess(
                executableURL: executableURL,
                arguments: arguments,
                environment: environment,
                timeout: timeout
            )
        }
        cachedCallArgumentAuditToolchainIdentity = identity
        return identity
    }

    static func callArgumentAuditRenderedBinding(
        instructionAddress: UInt64,
        document: PseudocodeDocument
    ) throws -> CallArgumentAuditRenderedBinding {
        let matchingLines = document.lines.filter { $0.sourceAddress == instructionAddress }
        guard matchingLines.count == 1, let line = matchingLines.first,
              let lineIndex = document.lines.firstIndex(where: {
                  $0.lineNumber == line.lineNumber
              }) else {
            throw ScriptingError.invalidArgument(
                "call at \(ScriptValue.hex(instructionAddress).stringValue ?? "") does not bind to exactly one rendered line"
            )
        }
        let lineBytes = Data(line.text.utf8)
        let occurrence = document.lines[..<lineIndex].reduce(into: 0) { count, prior in
            if Data(prior.text.utf8) == lineBytes { count += 1 }
        }
        return CallArgumentAuditRenderedBinding(
            line: line,
            occurrence: occurrence,
            utf8SHA256: sha256Hex(lineBytes)
        )
    }

    static func callArgumentAuditFocusIsStable(
        capturedSlot: ImageSlot,
        capturedBinary: BinaryImage,
        currentSlot: ImageSlot,
        currentSnapshot: WorkspaceSnapshot
    ) -> Bool {
        currentSlot == capturedSlot
            && currentSnapshot.binary(in: capturedSlot) == capturedBinary
    }

    private static func callArgumentAuditCallObject(
        instruction: MacIRInstruction,
        frame: MacIRCallFrame,
        document: PseudocodeDocument
    ) throws -> (value: ScriptValue, lineIdentity: String) {
        let binding = try callArgumentAuditRenderedBinding(
            instructionAddress: instruction.source.address,
            document: document
        )
        let line = binding.line
        let classifications = try callArgumentAuditSafeClassifications(
            frame: frame, renderedLine: line.text
        )
        let arguments = try frame.arguments.canonicalPhysicalEntriesForAudit.map { argument in
            guard let key = argument.location.physicalKey,
                  let classification = classifications[key] else {
                throw ScriptingError.invalidArgument(
                    "call argument lacks a canonical safe-render classification"
                )
            }
            return try callArgumentAuditArgumentObject(
                argument, classification: classification
            )
        }
        let controls = try frame.controlInputs.canonicalControlInputsForAudit.map {
            try callArgumentAuditControlObject($0)
        }
        let knownSignature: ScriptValue = if let target = frame.knownSignature?.target {
            try callArgumentAuditString(target, field: "known_signature_id")
        } else {
            .null
        }
        var fields: [String: ScriptValue] = [
            "instruction_address": .hex(instruction.source.address),
            "target": try callArgumentAuditString(frame.target, field: "call.target"),
            "known_signature_id": knownSignature,
            "tail_count_evidence": try callArgumentAuditTailObject(frame.tailCountEvidence),
            "rendered_line_ordinal": try callArgumentAuditInteger(
                line.lineNumber, field: "rendered_line_ordinal", minimum: 1
            ),
            "rendered_occurrence_ordinal": try callArgumentAuditInteger(
                binding.occurrence, field: "rendered_occurrence_ordinal", minimum: 0
            ),
            "rendered_utf8_sha256": .string(binding.utf8SHA256),
            "observation": try callArgumentAuditObservationObject(
                frame.arguments.observationScope
            ),
            "control_inputs": .array(controls),
            "arguments": .array(arguments),
        ]
        if let richArguments = frame.richArguments {
            fields["authored_rich_signature_id"] = .string(frame.target)
            fields["rich_source_arguments"] = .array(try richArguments.map { argument in
                .object([
                    "source_row": try callArgumentAuditString(argument.rowID.rawValue, field: "rich.source_row"),
                    "source_position": try callArgumentAuditInteger(argument.sourcePosition,
                        field: "rich.source_position", minimum: 0),
                    "type": try callArgumentAuditString(argument.type, field: "rich.type"),
                    "pieces": .array(try argument.pieces.map { piece in
                        let register: String
                        switch piece.register {
                        case let .simd(index, width): register = "\(width == 64 ? "d" : "s")\(index)"
                        case let .gpr(index, width): register = "\(width == 64 ? "x" : "w")\(index)"
                        }
                        return .object([
                            "register": .string(register),
                            "byte_offset": try callArgumentAuditInteger(piece.valueByteOffset,
                                field: "rich.piece.byte_offset", minimum: 0),
                            "size": try callArgumentAuditInteger(piece.size,
                                field: "rich.piece.size", minimum: 1),
                            "value_identity": try callArgumentAuditValueObject(piece.value),
                            "rendered": .bool(true),
                        ])
                    }),
                ])
            })
        }
        if let indirectResultPointer = frame.indirectResultPointer {
            fields["indirect_result_pointer"] = try callArgumentAuditValueObject(indirectResultPointer)
        }
        let value = ScriptValue.object(fields)
        return (value, "\(line.lineNumber):\(binding.occurrence)")
    }

    private static let registry: [String: Command] = {
        var commands: [Command] = []
        func add(_ name: String, _ summary: String, mutates: Bool = false, arguments: [String] = [],
                 _ run: @escaping @MainActor (ScriptValue, WorkspaceStore) throws -> ScriptValue) {
            if graphPageCommands.contains(name) {
                let args = arguments + ["page", "cursor", "detail"] + (arguments.contains("limit") ? [] : ["limit"])
                let description = " With page:true and detail:edges, returns bounded source-order direct edge pages without names. For affected xrefs to a known C string (or conservatively unclassified target), every row and every page, including empty partial and final pages, carries cfStringStorage {status: unavailable, reason: backingAddressNotRetained} for legacy data, {status: retained} when the CFString backing table is complete, or {status: partial, reason: cfStringWalkIncomplete} when it is not; equal text never adds edges. Rows to a C string that backs a retained CFString also include chained rows (via \"cfString\", cfString the object address) after the direct rows. A completed affected query with no rows is refused only when storage is unavailable or partial. Follow nextCursor even for empty partial pages; total is null until retained-edge traversal completes and then counts direct plus chained effective rows. coverage describes retained-edge traversal, not string-storage authority or whether analysis recovered every edge. Limit 1...500, default 100; cursors expire after five minutes or input mutation; older x1 cursors are refused. Callers/callees pages require a known function, carry no inferred string relationship and do not support selector/stub fallback."
                commands.append(Command(info: ScriptingCommandInfo(name: name, summary: summary + description,
                    mutates: mutates, arguments: args), run: { arguments, store in
                    if let page = try snapshotGraphPage(name, arguments: arguments, snapshot: store.snapshot,
                        context: store.graphPageContext, checkpoint: {}) { return page }
                    return try run(arguments, store)
                }))
                return
            }
            commands.append(Command(info: ScriptingCommandInfo(name: name, summary: summary, mutates: mutates, arguments: arguments), run: run))
        }

        // --- Introspection ---
        add("commands", "List the available scripting commands.") { _, _ in
            .array(availableCommands.map { info in
                .object([
                    "name": .string(info.name),
                    "summary": .string(info.summary),
                    "mutates": .bool(info.mutates),
                    "arguments": .array(info.arguments.map(ScriptValue.string)),
                ])
            })
        }

        add("info", "Summary of the loaded binary. stringCount is exact or null when unknown; stringRetainedCount and stringCountLowerBound are separate. stringCountCapped is null when unknown. Live info reports observed edit journal state without verifying file integrity, replay, or durability; startup info may contain only analysis status.", arguments: ["waitForReadyMs"]) { _, store in
            let snapshot = store.snapshot
            let binary = snapshot.binaries.first
            return .object([
                "name": .string(binary?.name ?? ""),
                "format": .string(binary?.kind ?? ""),
                "architecture": .string(binary?.architecture ?? ""),
                "slice": selectedSliceValue(binary),
                "editJournal": editJournalHealthValue(store),
                "functionCount": .int(Int64(snapshot.functions.count)),
                "instructionCount": .int(Int64(snapshot.instructions.count)),
                "symbolCount": .int(Int64(snapshot.symbols.count)),
                "stringLiteralCoverage": snapshot.stringLiteralCoverage.map { coverage in
                    .object(["status": .string(coverage.status),
                             "stopReason": coverage.stopReason.map { .string($0.rawValue) } ?? .null])
                } ?? .null,
            ].merging(try stringCountFields(snapshot)) { _, count in count })
        }

        add("slices", "List every architecture slice of the image's file: index, architecture (with subtype, e.g. arm64e), cpuType, cpuSubtype, offset, size, alignment and whether it is the analysed slice. Reads the primary image by default; `image` selects another loaded image.", arguments: [imageSelectorArgument]) { arguments, store in
            try imageSlices(arguments, snapshot: store.snapshot)
        }
        add("bundle-info", "Bundle and load context of the image: the enclosing app's Info.plist (bundle id, executable, versions, CFBundleDocumentTypes in full), UUID, platform, minimum OS, SDK, build tools, linked dylibs and a code-signing summary. No entitlements. Reads the primary image by default; `image` selects another loaded image.", arguments: [imageSelectorArgument]) { arguments, store in
            try bundleInfo(arguments, snapshot: store.snapshot)
        }

        // --- Reads ---
        add("reconstruction-jobs", "Durable Reconstruction job status: state, terminal reason, failed-task diagnostics, decompiler backend per task (native or macir + fallbackReason), and a completed source job's final synthesis (accepted revision, harness passed/total, provenance, elapsed), and the durable lifecycle (created/started/finished ms) with elapsed + elapsedSource (wall-clock, or phase-sum for older rows). Pass `job` (UUID) for one job.",
            arguments: ["job"]) { arguments, store in
            try reconstructionJobsStatus(arguments, state: store.reconstructionState,
                lifecycle: store.reconstructionLifecycle)
        }

        add("read-evidence", "Read app-authorized typed workspace evidence; integer identities use exact decimal strings.",
            arguments: ["operation"]) { arguments, store in
            try readEvidence(arguments, store: store, proposingPrincipal: .human)
        }
        add("functions", "List the primary image's discovered functions. `name` is the effective display name (a `rename` wins); every primary-image `function` selector accepts it, as well as an unambiguous raw analysis name. `page: true` returns {rows, total, isTruncated, nextCursor, sourceComplete}; `cursor` continues from `nextCursor`. Optional nameContains and regex filter display or raw names before limit; regex is at most 256 UTF-8 bytes.", arguments: ["limit", "page", "cursor", "nameContains", "regex"]) { arguments, store in
            try snapshotListRead("functions", arguments: arguments, snapshot: store.snapshot)
        }

        add("instructions", "Instructions of a function (by `function` display or raw name) or a range (`address`, `count`). With `annotate: true`, rows may also carry `to`, `kind` and `toName` (with `selector` and `toDemangled` as on `callees` rows) for a named direct call, or `to`, `kind`, `targetKind` and a `value` preview of at most 256 UTF-8 bytes (`valueTruncated` and `valueByteLength` when cut) for a recovered data reference; `operands` is unchanged; `annotate` defaults to false.",
            arguments: ["function", "address", "count", "annotate"]) { arguments, store in
            try snapshotListRead("instructions", arguments: arguments, snapshot: store.snapshot)
        }

        add("symbols", "List symbols. Optional nameContains, regex and kind filters apply before limit; regex is at most 256 UTF-8 bytes. page:true returns {rows, total, isTruncated, nextCursor, sourceComplete}; cursor continues from nextCursor.", arguments: ["limit", "page", "cursor", "nameContains", "regex", "kind"]) { arguments, store in
            try snapshotListRead("symbols", arguments: arguments, snapshot: store.snapshot)
        }

        add("strings", "List string literals. Optional section matches a qualified section exactly; contains is a case-insensitive literal substring. Unfiltered arrays use retained analysis. page:true discovers strings with bounded work; follow nextCursor even on an empty page. total is null until exact, totalLowerBound counts observed matches, and source identifies selectedSlice or retained fallback.", arguments: ["limit", "page", "cursor", "section", "contains"]) { arguments, store in
            try snapshotListRead("strings", arguments: arguments, snapshot: store.snapshot)
        }

        add("imports", "List dynamic imports. Optional nameContains matches import names literally and case-insensitively before limit; filtered reads may refuse on application-level admission budgets.", arguments: ["limit", "nameContains"]) { arguments, store in
            try snapshotListRead("imports", arguments: arguments, snapshot: store.snapshot)
        }

        add("exports", "List exported symbols. Optional nameContains matches export names literally and case-insensitively before limit; filtered reads may refuse on application-level admission budgets.", arguments: ["limit", "nameContains"]) { arguments, store in
            try snapshotListRead("exports", arguments: arguments, snapshot: store.snapshot)
        }

        add("sections", "List the binary's segments/sections, reflecting user renames and rebases; originalName carries the pre-override name. Optional nameContains matches the displayed name literally and case-insensitively before limit. Filtered reads refuse the whole result when application-level visit or UTF-8 admission budgets are exceeded.",
            arguments: ["limit", "nameContains"]) { arguments, store in
            try snapshotListRead("sections", arguments: arguments, snapshot: store.snapshot)
        }

        add("relocations", "List the binary's relocations (address, section, type, symbol, addend). Optional nameContains matches present symbol names literally and case-insensitively before limit; filtered reads may refuse on admission budgets.",
            arguments: ["limit", "nameContains"]) { arguments, store in
            try snapshotListRead("relocations", arguments: arguments, snapshot: store.snapshot)
        }

        add("read-bytes", "Read raw bytes at a virtual address as a hex string (default count 16, clamped to the section). Reads the primary image by default; `image` (a slot index or an image-owner ID) selects another loaded image. The result carries `imageSlot` and `imageOwner`. Over MCP, at most 100000 bytes per call; a larger count (after clamping to the section) is refused with code budgetExceeded, budget {unit: bytes, limit: 100000} and used.",
            arguments: ["address", "count", imageSelectorArgument]) { arguments, store in
            let snapshot = store.snapshot
            let target = try address(arguments, "address")
            let requested = try readBytesCount(arguments)
            // MS-19: the primary image unless `image` names another; for the primary slot these
            // are exactly the flat `sections`/`imageBytes` projections read before.
            let slot = try resolveImageSlot(arguments, snapshot: snapshot)
            let imageAnalysis = snapshot.analysis(in: slot)
            let provenance = imageProvenanceFields(slot: slot, snapshot: snapshot)
            func result(_ fields: [String: ScriptValue]) -> ScriptValue {
                .object(fields.merging(provenance) { _, label in label })
            }
            guard let section = (imageAnalysis?.sections ?? []).first(where: { $0.address <= target && target < $0.address &+ $0.size }) else {
                throw ScriptingError.invalidArgument("address \(ScriptValue.hex(target).stringValue ?? "") is not in any mapped section")
            }
            let delta = target - section.address
            // Clamp the read to the section end, then to the retained slice — all bounds
            // checked BEFORE any Int cast so a malformed fileOffset/size can't trap.
            let available = min(UInt64(requested), section.size - delta)
            // A zero-fill (BSS) section has no file bytes — its fileOffset is a placeholder,
            // so the in-memory image is zeros. Return zeros rather than reading the wrong
            // file region (which would otherwise be the slice header at fileOffset 0).
            if section.isZeroFill {
                let n = Int(min(available, UInt64(Int.max)))
                return result(["address": .hex(target), "length": .count(UInt64(n)), "hex": .string(String(repeating: "00", count: n))])
            }
            // Checked add: a malformed huge fileOffset must not WRAP into a small valid
            // index and silently return bytes from an unrelated file region.
            let (sliceStart, overflowed) = section.fileOffset.addingReportingOverflow(delta)
            let bytes = imageAnalysis?.imageBytes ?? Data()
            var hex = ""
            var length = 0
            if !overflowed, sliceStart <= UInt64(bytes.count) {
                let start = Int(sliceStart)
                let n = Int(min(available, UInt64(bytes.count - start)))
                let slice = bytes.subdata(in: start..<(start + n))
                hex = slice.map { String(format: "%02x", $0) }.joined()
                length = slice.count
            }
            return result(["address": .hex(target), "length": .count(UInt64(length)), "hex": .string(hex)])
        }

        add("xrefs", "Direct cross-references to (`to`) or from (`from`) an address, with same-image user add/suppress edits applied. Optional `limit` selects a prefix; excessive scan or result work is refused. Every row carries `imageSlot`; the optional `imageSlot` argument reads that image instead of the primary image. Flat rows also carry toName (the exact-address name of to, or null), fromFunction and fromFunctionName (the function containing from, or null), and selector, toDemangled and fromFunctionDemangled when they apply. For `to` a known C string, every returned row carries cfStringStorage: {status: unavailable, reason: backingAddressNotRetained} for legacy data, {status: retained} for a complete CFString backing table, or {status: partial, reason: cfStringWalkIncomplete} for an incomplete one, independently of literal coverage; rows to a C string that backs a retained CFString include chained rows after the direct rows (via \"cfString\", cfString the object address, same kind and from), and total on pages counts direct plus chained rows; classification is bounded and conservatively discloses uncertainty when exhausted. Equal text never proves storage identity or adds CFString edges. An affected query without rows is refused with preconditionFailed only when storage is unavailable or partial; explicit flat limit:0 retains the empty prefix. CFString-object and `from` queries retain direct rows. Paged edge rows omit names but preserve the same direct-edge and storage-authority contract.", arguments: ["to", "from", "limit", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            try snapshotListRead("xrefs", arguments: arguments, snapshot: store.snapshot)
        }

        add("function-references", "The data a function references: every non-call cross-reference whose source lies in the function, applying same-image additions and suppressions (by `function` display or raw name, or `address`; an address selects its containing function, including the exact start of a zero-width function; uncovered addresses are refused, never resolved to a preceding function). Each row is an xrefs row {from, to, kind, imageSlot, toName, fromFunction, fromFunctionName, plus selector, toDemangled and fromFunctionDemangled when they apply} with targetKind, plus value for strings, selectors, classes and imports; targetKind is cString, cfString, selector, class, import, symbol or data. CFString rows carry cfStringStorage {status: unavailable, reason: backingAddressNotRetained} for legacy data, or {status: retained, backing} / {status: partial, reason: cfStringWalkIncomplete} per the retained backing table; equal text never emits a cString storage address. Optional `limit` selects a prefix of surviving recovered rows followed by authored additions; the optional `imageSlot` argument reads that image instead of the primary image. Returns {name, start, end, imageSlot, imageOwner, stringLiteralCoverage, cfStringStorage, references, resolvedFunction, resolution}, plus requestedAddress for an address selection and demangled for covered Swift names. The top-level cfStringStorage disclosure (unavailable for legacy data, {status: retained} or {status: partial, reason: cfStringWalkIncomplete} per the backing table) is present independently of literal coverage, including empty results, zero limit and legacy data. This command is not paged. More than 5,000 references or 100,000 cross-reference/edit visits is refused with a typed budget refusal.", arguments: ["function", "address", "limit", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            try snapshotListRead("function-references", arguments: arguments, snapshot: store.snapshot)
        }

        add("endpoint-references", "Static candidates for where a network endpoint appears in the image: string literals whose host (case-insensitive, exact) matches `host`, optionally narrowed by `path` (literal or `{name}`, `%@`, `%d` template segments) and `method` (filters only strings that carry a method). `host` may be a bare host or an http, https, ws or wss URL; query values, fragments, user-info and ports are discarded and never echoed. Read-only and paged: returns {rows, total, isTruncated, nextCursor, sourceComplete, totalIsExact, imageSlot, evidence, query}. Each row is {evidence: staticCandidate, matchKind (exactURL, hostOnly, pathTemplate or pathComponent), stringAddress, cfStringAddress (null unless reached through a CFString), scheme, host, path (minimized, placeholders shown as :param), method, imageSlot, from, xrefKind, fromFunction, fromFunctionName, plus fromFunctionDemangled when it applies}; a matching string with no reference yields one row with null site fields (from, xrefKind, fromFunction, fromFunctionName), because an unreferenced match is still a static candidate. A row proves a string and a reference site only, never that the request is sent. `total` is exact only when sourceComplete is true. `image` selects a loaded image; the default is the primary image. Work over the snapshot budget is refused with a typed budget refusal.", arguments: ["host", "path", "method", imageSelectorArgument, "limit", "cursor"]) { arguments, store in
            try snapshotListRead("endpoint-references", arguments: arguments, snapshot: store.snapshot)
        }

        add("function-facts", "Stored function facts: ordered calls, references, branches, size and backend availability.", arguments: ["function", "address", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            try snapshotListRead("function-facts", arguments: arguments, snapshot: store.snapshot)
        }

        add("name-at", "The display name at an address in the primary image (custom name if set). Returns {name, demangled} for covered Swift names, otherwise a string or null.", arguments: ["address"]) { arguments, store in
            let snapshot = store.snapshot
            let target = try address(arguments, "address")
            let parsed = snapshot.functions.first(where: { $0.startAddress == target })?.name
                ?? snapshot.symbols.first(where: { $0.address == target })?.name
                ?? ""
            let name = snapshot.displayName(at: target, default: parsed)
            if let demangled = scriptingDemangled(name) {
                return .object(["name": .string(name), "demangled": .string(demangled)])
            }
            return name.isEmpty ? .null : .string(name)
        }

        add("containing-function", "The function containing an address: the first function, in list order, whose range [start, end) covers it (a zero-width function covers only its start). Reads the primary image by default; `image` (a slot index or an image-owner ID) selects another loaded image. Returns {name, start, end, imageSlot, imageOwner, resolvedFunction, requestedAddress, resolution}, plus demangled for covered Swift names; resolution is exact at the start, otherwise containing. An address outside every function is refused with code unknownSubject, naming the nearest preceding function and the section; there is no nearest-function fallback.", arguments: ["address", imageSelectorArgument]) { arguments, store in
            try snapshotListRead("containing-function", arguments: arguments, snapshot: store.snapshot)
        }

        add("annotation-gaps", "Read-only workspace annotation inventory across all stored image slots, independent of focus. Returns renamedFunctionsWithoutComment (custom name at an exact known function start, no authored comment there), unappliedTypes (current catalog types with no exact appliedTypeName in any stored override), and signaturesWithoutRename (nonempty authored signature, no custom name at the same image-qualified address; functionKnown may be false). Address rows carry imageSlot and imageOwner (null for an unloaded image). Retained overrides count as type applications. This reports current state, not historical never-use; no edits are blocked.") { _, store in
            try annotationGapsRead(snapshot: store.snapshot, checkpoint: {})
        }

        // --- Mutations (undoable through the store) ---
        // `rename` binds to the primary image — the image `functions`, `name-at` and the general
        // `function` selector read — not to live focus, so the label it writes is always the one
        // those commands report and resolve, whichever image the UI has focused.
        add("rename", "Set a custom name at an address in the primary image (the image `functions` and `name-at` read; independent of the focused image). Function-entry names are trimmed and limited to 256 UTF-8 bytes; empty clears. Adds requested, observed and verification fields from independent readback. Other addresses retain legacy writes with unsupportedTarget verification. Cost: one override commit on success, at most two with readback rollback, in one undo step; protected-override comparison and observer work grow with image size. For many edits use set-names.", mutates: true, arguments: ["address", "name"]) { arguments, store in
            let target = try address(arguments, "address")
            let name = try string(arguments, "name")
            return store.writeAnnotationWithReadback(at: target, in: store.snapshot.primarySlot, field: .name, text: name)
        }

        // Like `rename`, these address-authoring writes bind to the primary image — the image
        // whose comment/tag/label/bookmark reads report them — never to live focus.
        add("set-comment", "Set a comment at an address in the primary image (empty clears it; the image `instructions` reads; independent of the focused image). Function-entry comments are trimmed and limited to 2048 UTF-8 bytes. Adds requested, observed and verification fields from independent readback. Other addresses retain legacy writes with unsupportedTarget verification. Cost: one override commit on success, at most two with readback rollback, in one undo step; protected-override comparison and observer work grow with image size. For many edits use set-comments.", mutates: true, arguments: ["address", "comment"]) { arguments, store in
            let target = try address(arguments, "address")
            let comment = try string(arguments, "comment")
            return store.writeAnnotationWithReadback(at: target, in: store.snapshot.primarySlot, field: .comment, text: comment)
        }

        add("set-tag", "Set a free-text tag at an address in the primary image (empty clears it; independent of the focused image). Cost: at most one override commit and one undo step per call; remaining observer work grows with image size.", mutates: true, arguments: ["address", "tag"]) { arguments, store in
            let target = try address(arguments, "address")
            let tag = try string(arguments, "tag")
            store.setTag(target, in: store.snapshot.primarySlot, tag: tag.isEmpty ? nil : tag)
            return .object(["ok": .bool(true), "address": .hex(target)])
        }

        for (command, field, action) in [
            ("set-names", "name", "Set primary-image names in one batch; empty text clears."),
            ("set-comments", "comment", "Set primary-image comments in one batch; empty text clears."),
            ("set-local-labels", "label", "Set primary-image local labels in one batch; empty text clears."),
            ("set-operand-formats", "format", "Set primary-image operand formats in one batch; empty text clears."),
            ("set-types", "type", "Set primary-image type names in one batch; empty text clears and unresolved names remain stored.")
        ] {
            let structuralCost = (field == "format" || field == "type")
                ? " Clearing legacy structural metadata can trigger reanalysis."
                : ""
            add(command, action + " Cost: at most one slot-map operation and one undo step for the whole batch (at most 1024 entries)." + structuralCost,
                mutates: true, arguments: ["entries"]) { arguments, store in
                guard let entries = arguments["entries"]?.arrayValue else {
                    throw ScriptingError.invalidArgument("entries[0]: entries must be an array")
                }
                guard !entries.isEmpty else {
                    throw ScriptingError.invalidArgument("entries[0]: at least one entry is required")
                }
                guard entries.count <= 1024 else {
                    throw ScriptingError.invalidArgument("entries[1024]: at most 1024 entries are allowed")
                }
                var seen: Set<UInt64> = []
                var parsed: [(address: UInt64, text: String)] = []
                parsed.reserveCapacity(entries.count)
                for (index, value) in entries.enumerated() {
                    guard case .object(let entry) = value, Set(entry.keys) == ["address", field] else {
                        throw ScriptingError.invalidArgument("entries[\(index)]: expected address and \(field) only")
                    }
                    guard let address = entry["address"]?.addressValue else {
                        throw ScriptingError.invalidArgument("entries[\(index)].address: invalid address")
                    }
                    guard let text = entry[field]?.stringValue else {
                        throw ScriptingError.invalidArgument("entries[\(index)].\(field): expected a string")
                    }
                    if field == "format", !text.isEmpty, OperandFormat(rawValue: text) == nil {
                        throw ScriptingError.invalidArgument("entries[\(index)].format: invalid operand format")
                    }
                    guard seen.insert(address).inserted else {
                        throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address")
                    }
                    parsed.append((address, text))
                }
                let slot = store.snapshot.primarySlot
                // Types and labels gained VI1 in #272 (below); names, comments and operand
                // formats gain it after them.
                if field == "type" || field == "label" {
                    return try ScriptingWriteReadback.overrides(command: command, store: store, slot: slot,
                        field: field == "type" ? .type : .label,
                        expected: parsed.map { ($0.address, ScriptingWriteReadback.text($0.text)) }) {
                            let changed = field == "type"
                                ? store.setAppliedTypes(parsed.map { ($0.address, Optional($0.text)) }, in: slot)
                                : store.setLocalLabels(parsed.map { ($0.address, Optional($0.text)) }, in: slot)
                            if MCPBatchReceiptBudget.commands.contains(command) {
                                ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(entries.count),
                                    changed: Int64(changed), imageSlot: Int64(slot.rawValue)))
                            }
                            return .object(["ok": .bool(true), "count": .int(Int64(entries.count)),
                                            "changed": .int(Int64(changed))])
                        }
                }
                // VI1-B: names, comments and operand formats read back per item. The reply keeps
                // its legacy keys; requested/observed/verification/readback are additive.
                return try ScriptingWriteReadback.overrideBatch(command: command, store: store, slot: slot,
                    expected: parsed.map { entry in
                        (entry.address, field == "format"
                            ? (OperandFormat(rawValue: entry.text).map { ScriptValue.string($0.rawValue) } ?? .null)
                            : ScriptingWriteReadback.text(entry.text))
                    },
                    project: { override in
                        switch field {
                        case "name": return ScriptingWriteReadback.text(override.customName)
                        case "format": return override.operandFormat.map { ScriptValue.string($0.rawValue) } ?? .null
                        default: return ScriptingWriteReadback.text(override.customComment)
                        }
                    }) {
                    let changed: Int
                    if field == "name" {
                        changed = store.setCustomNames(parsed.map { (address: $0.address, name: Optional($0.text)) },
                                                       in: slot)
                    } else if field == "type" {
                        changed = store.setAppliedTypes(parsed.map { (address: $0.address, name: Optional($0.text)) },
                                                        in: slot)
                    } else if field == "format" {
                        changed = store.setOperandFormats(parsed.map { (address: $0.address, format: OperandFormat(rawValue: $0.text)) },
                                                          in: slot)
                    } else if field == "label" {
                        changed = store.setLocalLabels(parsed.map { (address: $0.address, label: Optional($0.text)) },
                                                       in: slot)
                    } else {
                        changed = store.setCustomComments(parsed.map { (address: $0.address, comment: Optional($0.text)) },
                                                          in: slot)
                    }
                    if MCPBatchReceiptBudget.commands.contains(command) {
                        ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(entries.count),
                                                                            changed: Int64(changed), imageSlot: Int64(slot.rawValue)))
                    }
                    return .object(["ok": .bool(true), "count": .int(Int64(entries.count)),
                                    "changed": .int(Int64(changed))])
                }
            }
        }
        for (command, field, colors) in [("set-tags", "tag", false), ("set-colors", "color", true)] {
            add(command, "Set 1–1024 primary-image \(field) annotations in one undoable batch. All entries are validated before mutation; an empty value clears.", mutates: true, arguments: ["entries"]) { arguments, store in
                guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"],
                      let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
                    throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
                }
                var seen = Set<UInt64>()
                var edits: [(address: UInt64, text: String)] = []
                for (index, value) in entries.enumerated() {
                    guard case .object(let row) = value, Set(row.keys) == ["address", field],
                          let address = row["address"]?.addressValue, let text = row[field]?.stringValue else {
                        throw ScriptingError.invalidArgument("entries[\(index)]: expected address and \(field) only")
                    }
                    guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
                    if colors && !text.isEmpty && ColorTag(rawValue: text) == nil {
                        throw ScriptingError.invalidArgument("entries[\(index)].color: invalid color")
                    }
                    edits.append((address, text))
                }
                try Task.checkCancellation()
                let slot = store.snapshot.primarySlot
                return try ScriptingWriteReadback.overrideBatch(command: command, store: store, slot: slot,
                    expected: edits.map { edit in
                        (edit.address, colors
                            ? (ColorTag(rawValue: edit.text).map { ScriptValue.string($0.rawValue) } ?? .null)
                            : ScriptingWriteReadback.text(edit.text))
                    },
                    project: { override in
                        colors ? (override.colorTag.map { ScriptValue.string($0.rawValue) } ?? .null)
                               : ScriptingWriteReadback.text(override.tag)
                    }) {
                    let result = store.setTagColorsBatch(edits, in: slot, colors: colors)
                    ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(entries.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                    return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(entries.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
                }
            }
        }
        add("undo-last", "Undo the last top-level step in a headless session. Cost: one undo step; undoing a structural edit re-runs analysis before the reply.",
            mutates: true) { _, store in
            let manager = store.undoManager
            guard manager.groupingLevel == 0 else {
                throw ScriptingError.invalidArgument("an undo group is open; retry")
            }
            guard manager.canUndo else { throw ScriptingError.invalidArgument("nothing to undo") }
            let action = manager.undoActionName
            manager.undo()
            return .object(["ok": .bool(true), "undone": .string(action), "canUndo": .bool(manager.canUndo)])
        }


        // --- Navigation / search ---
        // `goto` is classified as mutating. It is not a durable authoring edit (no undo entry, no
        // dirty mark), but it changes shared MainActor workspace state that later commands observe:
        // the focused image (which `overrideKey` uses to target every subsequent authoring edit),
        // the selection, the editor mode, navigation history and the native-decompiler drive.
        // The mutation classification is what keeps that truthful at every binding: MCP serializes
        // it with other mutations in arrival order, a queued goto cancelled before admission never
        // runs, the async path checks cancellation immediately before the synchronous commit, and a
        // goto that already navigated is reported as committed rather than "cancelled".
        add("goto", "Navigate to a hex address or symbol name.", mutates: true, arguments: ["query"]) { arguments, store in
            let query = try string(arguments, "query")
            let ok = store.goTo(query: query)
            return .object(["ok": .bool(ok), "address": store.selectedAddress.map(ScriptValue.hex) ?? .null])
        }

        add("search", "Search the binary (`mode`: text | regex | hex). The query is at most 256 UTF-8 bytes; a longer query, or an invalid regex, is refused with {error: invalidPattern, detail}. Every result row carries `imageSlot`; the optional `imageSlot` argument restricts the search to one loaded image. Optional `kind` selects instruction, string, symbol or function for text/regex, or bytes for hex. Async scanning selects the kind before spending its visit budget and refuses an incomplete zero-hit scan; a nonempty partial result retains isTruncated and lowerBound. A stopped bounded search returns its rows with nextCursor (pass it back as cursor, with the same query, mode, kind and imageSlot); with no rows it returns {error: refused, refusal: {code: budgetExceeded, budget, used, narrowing, kindsCovered, kindsPending, nextCursor}}; a complete search lists kindsCovered.",
            arguments: ["query", "mode", "kind", "cursor", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            try searchSynchronously(arguments, store: store, validateDirectHex: true)
        }

        add("neon-hitrate", "One bounded libjpeg.8.dylib NEON instruction and exact typed MacIR lift measurement.") { _, store in
            try Self.libjpegNEONHitRate(snapshot: store.snapshot)
        }

        // --- Decompiler ---
        add("decompile", "Pseudocode for a function (by `function` display or raw name, or `address`) in the primary image by default; `image` (a slot index or an image-owner ID) selects another loaded image, and the focused image is never implied. An address must be inside the selected function (a zero-width function accepts only its start); uncovered addresses are refused with nearest-function and section context. A supplied function name takes precedence. Object replies include resolvedFunction and resolution, plus requestedAddress for an address selector. MCP tries the native SLEIGH decompiler first; the result's `backend` is `native` or `macir`, a MacIR result carries `fallbackReason` (`native-unavailable`, `native-empty`, or `native-failed: <code>`), and every result names the image that answered in `imageSlot` and `imageOwner`. A function over 262144 bytes or 8192 basic blocks is refused before lifting (\"function too large: N bytes, M blocks\"); an MCP decompile with no result within 27000 ms is refused with that budget instead of the request deadline. Optional format (text or lines), inclusive positional lineRange (a-b), and cursor select whole-line output pages; MCP defaults to text. Shaped replies use a 200000-byte frame-plus-LF budget, measured with id 1 and the single-generation envelope in both protocols. Code is paged first; whole optional fields may then be named in omittedFields with responseComplete false; an oversized minimum reply is refused with budgetExceeded. One oversized first line on a single-backend page is retained whole with required fields and omission disclosure. backend both shares one budget, reduces native code before MacIR, and cannot accompany cursor; continue each nested cursor with its own native or macir backend. Continuations require the same selector, image, document generation and fold mode. Optional `backend` (native, macir or both) chooses or compares; a MacIR result also carries `fallbackCause` and `fallbackDetail`, and a native result may carry `cache` (hit or miss) and `generation`. Optional `fold` (array; supported: \"arc\") removes proven ARC retain/release import calls from the MacIR rendering (non-SSA only; SSA functions are returned unchanged and the refusal is disclosed). It selects MacIR (reason `fold-requires-macir`) and is refused with backend native or both. Replies add `folded` ({arc: N}), `foldedEvents` (page-bounded, at most 500, with `foldedEventsTruncated`) and `foldRefused`.", arguments: ["function", "address", imageSelectorArgument, "format", "lineRange", "cursor", "backend", "fold"]) { arguments, store in
            try runSnapshotRead(.decompile, arguments: arguments,
                context: ScriptingSnapshotReadContext(snapshot: store.snapshot, focusedSlot: store.focusedImageSlot),
                checkpoint: {})
        }

        add(
            "parameter-binding-audit",
            "Candidate-only structural parameter binding facts from typed MacIR argument nodes (focused image; `function` display or raw name, or `address`).",
            arguments: ["function", "address"]
        ) { arguments, store in
            try runSnapshotRead(.parameterBindingAudit, arguments: arguments,
                context: ScriptingSnapshotReadContext(snapshot: store.snapshot, focusedSlot: store.focusedImageSlot),
                checkpoint: {})
        }

        add(
            "call-argument-audit",
            "Candidate-only structural call argument facts from one rendered MacIR function (focused image; exactly one of `function` raw structural name or `address`; display renames are not selectors).",
            arguments: ["function", "address"]
        ) { arguments, store in
            let slot = store.focusedImageSlot
            let snapshot = store.snapshot
            guard slot.rawValue >= 0,
                  let binary = snapshot.binary(in: slot),
                  let analysis = snapshot.analysis(in: slot) else {
                throw ScriptingError.invalidArgument(
                    "no bounded analyzed image exists in the focused slot"
                )
            }
            let function = try resolveCallArgumentAuditFunction(
                arguments, in: analysis.functions
            )
            let binaryURL = URL(fileURLWithPath: binary.path)
            let executableURL = try runningExecutableURL()
            let initialBinaryFingerprint = try callArgumentAuditFileFingerprint(at: binaryURL)
            let initialExecutableFingerprint = try callArgumentAuditFileFingerprint(
                at: executableURL
            )
            let overrides = snapshot.overrides(in: slot)
            let instructions = analysis.instructions.filter { row in
                let override = overrides[row.address]
                let isExcludedFromCode = override.map {
                    $0.isData || $0.isUndefined || !($0.dataShape?.isEmpty ?? true)
                } ?? false
                guard row.address >= function.startAddress, !isExcludedFromCode else {
                    return false
                }
                return function.endAddress > function.startAddress
                    ? row.address < function.endAddress
                    : row.address == function.startAddress
            }

            let machineUsage = snapshot.machineCallUsageHandoff(
                for: (function: function, instructions: instructions), in: slot)

            // This is the command's single MacIR construction. Render and audit this exact
            // object; do not call a convenience printer overload that would rebuild it.
            let printer = PseudocodePrinter()
            let irFunction = printer.buildFunction(
                functionName: function.name,
                startAddress: function.startAddress,
                jumpTables: snapshot.resolvedJumpTables(in: slot),
                objcSelectors: analysis.objcSelectors,
                constantStrings: analysis.constantStrings,
                signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
                authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
                directCallVoidResultTargets: snapshot.directCallVoidResultTargets(in: slot),
                machineCallUsage: machineUsage?.usage,
                machineUsageContext: machineUsage?.context,
                types: snapshot.typeDefinitions,
                instructions: instructions
            )
            // Audit output is structural. Presentation-only function/call/register overlays
            // are intentionally absent, while signature overrides already participated above.
            try Task.checkCancellation()
            let document = printer.print(
                function: irFunction,
                ownDirectCallAddresses: snapshot.ownDirectCallAddresses(in: slot),
                types: snapshot.typeDefinitions
            )
            try Task.checkCancellation()

            let structuralCalls: [(instruction: MacIRInstruction, frame: MacIRCallFrame)] =
                irFunction.instructions.compactMap { instruction in
                    guard case let .call(frame, _) = instruction.operation else { return nil }
                    return (instruction, frame)
                }.sorted { left, right in
                    left.instruction.source.address < right.instruction.source.address
                }
            for pair in zip(structuralCalls, structuralCalls.dropFirst())
            where pair.0.instruction.source.address == pair.1.instruction.source.address {
                throw ScriptingError.invalidArgument("call audit contains a duplicate call address")
            }

            var lineIdentities: Set<String> = []
            var callValues: [ScriptValue] = []
            callValues.reserveCapacity(structuralCalls.count)
            for structuralCall in structuralCalls {
                if let signatureTarget = structuralCall.frame.knownSignature?.target,
                   signatureTarget != structuralCall.frame.target {
                    throw ScriptingError.invalidArgument(
                        "call target and known signature identity disagree"
                    )
                }
                let serialized = try callArgumentAuditCallObject(
                    instruction: structuralCall.instruction,
                    frame: structuralCall.frame,
                    document: document
                )
                guard lineIdentities.insert(serialized.lineIdentity).inserted else {
                    throw ScriptingError.invalidArgument(
                        "call audit duplicates a rendered call-line identity"
                    )
                }
                callValues.append(serialized.value)
            }

            let toolchainIdentity = try activeToolchainIdentityObject()

            // Re-resolve and re-fingerprint both complete files, then recheck the exact
            // focus immediately before publication. This detects symlink retargeting,
            // atomic replacement, content drift, and cross-image focus changes.
            let finalBinaryFingerprint = try callArgumentAuditFileFingerprint(at: binaryURL)
            let finalExecutableURL = try runningExecutableURL()
            let finalExecutableFingerprint = try callArgumentAuditFileFingerprint(
                at: finalExecutableURL
            )
            let liveSnapshot = store.snapshot
            guard callArgumentAuditFocusIsStable(
                capturedSlot: slot,
                capturedBinary: binary,
                currentSlot: store.focusedImageSlot,
                currentSnapshot: liveSnapshot
            ),
            finalBinaryFingerprint == initialBinaryFingerprint,
            finalExecutableURL == executableURL,
            finalExecutableFingerprint == initialExecutableFingerprint else {
                throw ScriptingError.invalidArgument(
                    "focused image or bound whole-file provenance changed during the audit"
                )
            }
            return .object([
                "schema": .string("call-argument-audit-v1"),
                "validation_scope": .string("structural-candidate"),
                "combined_oracle_comparison": .bool(false),
                "image_slot": .int(Int64(slot.rawValue)),
                "binary_sha256": .string(initialBinaryFingerprint.sha256),
                "producer_executable_sha256": .string(initialExecutableFingerprint.sha256),
                "toolchain_identity": toolchainIdentity,
                "function": .object([
                    "start_address": .hex(function.startAddress),
                    "display_name": try callArgumentAuditString(
                        function.name, field: "function.display_name", allowEmpty: true
                    ),
                ]),
                "calls": .array(callValues),
            ])
        }

        // --- Call graph ---
        add("call-graph", "Bounded raw explicit-call BFS for one image (primary by default). root is a function address; direction is callers or callees (default callees); depth 0...16 (default 4); limit 1...100 (default 100). Named nodes and callsite edges are page deltas. Follow nextCursor, including empty partial pages, repeating selectors; limit may be reduced. completeWithinScope describes captured retained traversal, sourceComplete remains null. Cursors expire after five minutes or input change; no manual or cross-image edges.",
            arguments: ["root", "depth", "direction", "limit", "cursor", imageSlotFilterArgument]) { arguments, store in
            try boundedCallRead("call-graph", arguments: arguments, snapshot: store.snapshot,
                                context: store.graphPageContext, checkpoint: {})
        }
        add("call-path", "Bounded directed shortest-hop search over one image's raw explicit calls. from/to select containing functions; maxDepth 0...16 (default 4). limit 1...100 (default 100) bounds traversal output work per page. Follow nextCursor with the same selectors, including empty partial pages (incompleteReason resumeNextCursor): the raw-call scan resumes across pages. Continue it even after a witness appears. witnessExists is null until a witness is found or the search completes. edges repeats the current witness, not a page delta. witnessExists, sourceComplete and shortestHopProven are independent; shortestHopProven is conservative until completeWithinScope. Proof is only about retained raw calls, not missing dynamic calls. No effective overlays or live-freshness claim.",
            arguments: ["from", "to", "maxDepth", "limit", "cursor", imageSlotFilterArgument]) { arguments, store in
            try boundedCallRead("call-path", arguments: arguments, snapshot: store.snapshot,
                                context: store.graphPageContext, checkpoint: {})
        }
        add("callers", "Call sites that target a function (by function display or raw name, or address). An address inside a known function selects that function, including a zero-width function at its start. An address or stub name outside every function returns the call-kind sites of xrefs with to, with fromFunction and fromFunctionName; zero sites preserve the refusal, and finite work/result budgets still apply. A supplied function name takes precedence over address. Every row carries imageSlot; the optional imageSlot argument reads that image instead of the primary image. Every row also carries toName (the exact-address name of to, or null), fromFunction and fromFunctionName (the function containing from, or null), and selector, toDemangled and fromFunctionDemangled when they apply. With `selector` (an Objective-C selector such as \"setDouble:forKey:\") instead of `function` or `address`, returns every send site of that selector, through its _objc_msgSend$ stub (via \"stub\"), direct branches to that stub (via \"stubBranch\") and its selector references (via \"selref\"), each with its containing function. With `selectors` (1 to 8 selectors) instead, returns the union of their send-site rows in one reply, sorted by from, to and selector; use it instead of repeated selector calls.",
            arguments: ["function", "address", "selector", "selectors", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            if try selectorArgument(arguments) != nil || selectorsArgument(arguments) != nil {
                return try selectorSendSiteRows(arguments, snapshot: store.snapshot, checkpoint: {})
            }
            let snapshot = store.snapshot
            let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
            let view = filter.map { imageProjection(of: snapshot, in: $0) } ?? snapshot
            let function: FunctionSummary
            do {
                function = try resolveFunction(arguments, view)
            } catch let error as ScriptingError {
                if case .ambiguousObjCMethodSelector = error { throw error }
                if let rows = try stubCallerRows(arguments: arguments, snapshot: snapshot, view: view,
                    filter: filter, scope: .nonattached, checkpoint: {}) { return rows }
                throw error
            }
            try requireCallersContainment(arguments, function: function)
            let slot = filter ?? view.primarySlot
            return .array(try namedGraphRows(view.callers(of: function), includeKind: false,
                snapshot: view, slot: slot, checkpoint: {}))
        }
        add("callees", "Functions called from within a function (by `function` display or raw name, or `address`). An address selects its containing function, including the exact start of a zero-width function; uncovered addresses are refused, never resolved to a preceding function. A supplied function name takes precedence. Replies remain bare arrays. Every row carries `imageSlot`; the optional `imageSlot` argument reads that image instead of the primary image. Every row also carries toName (the exact-address name of to, or null), fromFunction and fromFunctionName (the function containing from, or null), and selector, toDemangled and fromFunctionDemangled when they apply.",
            arguments: ["function", "address", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            let snapshot = store.snapshot
            let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
            let view = filter.map { imageProjection(of: snapshot, in: $0) } ?? snapshot
            let function = try resolveFunction(arguments, view)
            let slot = filter ?? view.primarySlot
            return .array(try namedGraphRows(view.callees(of: function), includeKind: false,
                snapshot: view, slot: slot, checkpoint: {}))
        }

        add("implementations", "Every Objective-C class and category method that implements a selector (`selector`, required): class, category, isClassMethod, address (the IMP) and name. Protocol declarations are not listed; an unknown selector returns [].", arguments: ["selector", WorkspaceScriptingAPI.imageSlotFilterArgument]) { arguments, store in
            try selectorImplementationRows(arguments, snapshot: store.snapshot, checkpoint: {})
        }

        add("basic-blocks", "Control-flow basic blocks of a function (by `function` display or raw name, or `address`), each with its outgoing edges. An address must be contained in the function, or equal the start of a zero-width function; otherwise it is refused with nearest-function and section context. A supplied function name takes precedence. Replies remain bare arrays.",
            arguments: ["function", "address"]) { arguments, store in
            try runSnapshotRead(.basicBlocks, arguments: arguments,
                context: ScriptingSnapshotReadContext(snapshot: store.snapshot, focusedSlot: store.focusedImageSlot),
                checkpoint: {})
        }
        add("resolve-symbol", "Resolve a symbol name to an address.", arguments: ["name"]) { arguments, store in
            store.snapshot.address(forSymbolName: try string(arguments, "name")).map(ScriptValue.hex) ?? .null
        }

        add("demangle", "Render one Swift mangled name ($s, $S, _$s, _$S or _TtC prefix, at most 8192 bytes) with the in-tree demangler. Reply: {name, demangled, language}. Uncovered, non-Swift or over-budget names are refused. Cost: one bounded parse; no workspace read.",
            arguments: ["name"]) { arguments, _ in
            try demangleReply(arguments)
        }

        // --- Authoring: types / signatures / formats (all undoable) ---
        // Like `rename`, `set-type`, `set-color`, `set-operand-format` and the make-* marks bind to
        // the primary image (the image `functions`/`instructions`/`decompile` read and whose
        // analysis a structural mark re-drives), never to live focus. Patches also target primary
        // to match scripted export. Signatures stay focused, matching the focused audits.
        add("set-type", "Apply a type name at an address in the primary image (empty clears; independent of the focused image). Cost: at most one override update and one undo step; clearing legacy structural metadata can trigger reanalysis. For multiple edits use set-types.", mutates: true, arguments: ["address", "type"]) { arguments, store in
            let target = try address(arguments, "address")
            let type = try string(arguments, "type")
            let slot = store.snapshot.primarySlot
            return try ScriptingWriteReadback.overrides(command: "set-type", store: store, slot: slot,
                field: .type, expected: [(target, ScriptingWriteReadback.text(type))]) {
                    store.setAppliedType(target, in: slot, name: type.isEmpty ? nil : type)
                    return .object(["ok": .bool(true), "address": .hex(target)])
                }
        }
        add("set-signature", "Set a function's signature in the focused image (the image parameter-binding-audit and call-argument-audit read; decompile reads the primary image): returnType, tri-state args, variadicState, and noReturnState.",
            mutates: true, arguments: ["address", "returnType", "args", "variadicState", "noReturnState", "isNoReturn"]) { arguments, store in
            let target = try address(arguments, "address")
            let existing = store.snapshot.addressOverrides[store.overrideKey(target)]?.signature

            let signature = try mergedSignature(arguments, existing: existing)
            let slot = store.overrideKey(target).slot
            return try ScriptingWriteReadback.overrides(command: "set-signature", store: store, slot: slot,
                field: .signature, expected: [(target, try ScriptingWriteReadback.signature(signature))]) {
                    store.setSignature(target, signature)
                    return .object(["ok": .bool(true), "address": .hex(target)])
                }
        }
        add("set-signatures", "Set 1–1024 focused-image signatures in one undoable batch. All entries are parsed and merged before mutation.", mutates: true, arguments: ["entries"]) { arguments, store in
            guard case .object(let fields) = arguments, Set(fields.keys) == ["entries"],
                  let entries = fields["entries"]?.arrayValue, !entries.isEmpty, entries.count <= 1024 else {
                throw ScriptingError.invalidArgument("entries: expected 1–1024 entries only")
            }
            let allowed: Set<String> = ["address", "returnType", "args", "variadicState", "noReturnState", "isNoReturn"]
            let slot = store.focusedImageSlot
            let snapshot = store.snapshot
            var seen = Set<UInt64>()
            var edits: [(address: UInt64, signature: FunctionSignatureOverride)] = []
            for (index, entry) in entries.enumerated() {
                guard case .object(let row) = entry, Set(row.keys).isSubset(of: allowed), let address = row["address"]?.addressValue else {
                    throw ScriptingError.invalidArgument("entries[\(index)]: expected address and signature fields only")
                }
                guard seen.insert(address).inserted else { throw ScriptingError.invalidArgument("entries[\(index)].address: duplicate address") }
                let existing = snapshot.addressOverrides[ImageAddress(slot: slot, address: address)]?.signature
                edits.append((address, try mergedSignature(entry, existing: existing)))
            }
            try Task.checkCancellation()
            return try ScriptingWriteReadback.overrides(command: "set-signatures", store: store, slot: slot,
                field: .signature, expected: try edits.map { ($0.address, try ScriptingWriteReadback.signature($0.signature)) }) {
                    let result = store.setSignaturesBatch(edits, in: slot)
                    ScriptingBatchReceiptCapture.current?.record(.init(command: "set-signatures", count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                    return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
                }
        }
        add("set-color", "Set a color tag at an address in the primary image (red/orange/yellow/green/blue/purple/gray; empty clears; independent of the focused image). Cost: at most one override commit and one undo step per call; remaining observer work grows with image size.",
            mutates: true, arguments: ["address", "color"]) { arguments, store in
            let target = try address(arguments, "address")
            let color = try string(arguments, "color")
            let slot = store.snapshot.primarySlot
            if color.isEmpty {
                store.setColorTag(target, in: slot, color: nil)
            } else if let tag = ColorTag(rawValue: color) {
                store.setColorTag(target, in: slot, color: tag)
            } else {
                // Don't silently clear on a typo'd value — surface it.
                throw ScriptingError.invalidArgument("color must be one of \(ColorTag.allCases.map(\.rawValue).joined(separator: "|"))")
            }
            return .object(["ok": .bool(true), "address": .hex(target)])
        }
        add("set-operand-format", "Format an immediate operand at an address in the primary image (hex/decimal/character/unsignedDecimal/octal/binary/negativeHex; empty clears; independent of the focused image). Cost: at most one override update and one undo step; clearing legacy structural metadata can trigger reanalysis. For multiple edits use set-operand-formats.",
            mutates: true, arguments: ["address", "format"]) { arguments, store in
            let target = try address(arguments, "address")
            let format = try string(arguments, "format")
            let slot = store.snapshot.primarySlot
            if format.isEmpty {
                store.setOperandFormat(target, in: slot, nil)
            } else if let parsed = OperandFormat(rawValue: format) {
                store.setOperandFormat(target, in: slot, parsed)
            } else {
                throw ScriptingError.invalidArgument("format must be one of \(OperandFormat.allCases.map(\.rawValue).joined(separator: "|"))")
            }
            return .object(["ok": .bool(true), "address": .hex(target)])
        }
        for (command, field, procedures) in [("set-data", "isData", false), ("set-procedures", "isProcedure", true)] {
            add(command, "Set 1–1024 primary-image data or procedure marks in one undoable batch. Omitted mark defaults to true.", mutates: true, arguments: ["entries"]) { arguments, store in
                let values = try dataProcedureBatchEntries(arguments, procedures: procedures)
                let slot = store.snapshot.primarySlot
                let edits = try values.map { value in (address: try address(value, "address"), value: value[field]?.boolValue ?? true) }
                try Task.checkCancellation()
                return try ScriptingWriteReadback.overrideBatch(command: command, store: store, slot: slot,
                    expected: edits.map { ($0.address, ScriptValue.bool($0.value)) },
                    project: { .bool(procedures ? $0.markAsProcedure : $0.isData) },
                    flagIsolation: procedures) {
                    let result = store.setDataProcedureBatch(edits, in: slot, procedures: procedures)
                    ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                    return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
                }
            }
        }
        add("make-data", "Mark an address in the primary image as data (true) or code (false). Re-drives the primary image's analysis (what `functions`/`instructions` read; independent of the focused image).", mutates: true, arguments: ["address", "isData"]) { arguments, store in
            let target = try address(arguments, "address")
            if let value = arguments["isData"], value.boolValue == nil {
                throw ScriptingError.invalidArgument("isData must be a boolean")
            }
            let isData = arguments["isData"]?.boolValue ?? true
            store.setIsData(target, in: store.snapshot.primarySlot, isData)
            return .object(["ok": .bool(true), "address": .hex(target), "isData": .bool(isData)])
        }
        add("make-procedure", "Force a function start at an address in the primary image (true) or clear it (false). Re-drives the primary image's discovery (what `functions` lists; independent of the focused image).",
            mutates: true, arguments: ["address", "isProcedure"]) { arguments, store in
            let target = try address(arguments, "address")
            if let value = arguments["isProcedure"], value.boolValue == nil {
                throw ScriptingError.invalidArgument("isProcedure must be a boolean")
            }
            let isProcedure = arguments["isProcedure"]?.boolValue ?? true
            store.setMarkAsProcedure(target, in: store.snapshot.primarySlot, isProcedure)
            return .object(["ok": .bool(true), "address": .hex(target), "isProcedure": .bool(isProcedure)])
        }
        add("make-arrays", "Mark 1–1024 primary-image array addresses in one undoable batch. All entries are validated before one structural reanalysis dispatch.", mutates: true, arguments: ["entries"]) { arguments, store in
            let values = try arrayShapeBatchEntries(arguments)
            let slot = store.snapshot.primarySlot
            let edits = try values.map { value in
                guard case let .int(count)? = value["count"] else { throw ScriptingError.invalidArgument("count must be an integer") }
                let type = value["elementType"]?.stringValue
                let format = value["format"]?.stringValue
                let parsed = format.flatMap { OperandFormat(rawValue: $0) }
                return (address: try address(value, "address"), elementType: (type?.isEmpty == false) ? type : nil, count: Int(count), format: parsed)
            }
            try Task.checkCancellation()
            return try ScriptingWriteReadback.overrideBatch(command: "make-arrays", store: store, slot: slot,
                expected: try edits.map { edit in
                    (edit.address, try ScriptingWriteReadback.dataShape(DataShapeOverride(kind: .array, elementType: edit.elementType,
                        elementCount: edit.count, elementDisplayFormat: edit.format)))
                },
                project: { (try? ScriptingWriteReadback.dataShape($0.dataShape)) ?? .null }) {
                let result = store.makeArraysBatch(edits, in: slot)
                ScriptingBatchReceiptCapture.current?.record(.init(command: "make-arrays", count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
            }
        }
        add("make-array", "Mark an address in the primary image (independent of the focused image) as an array of `count` elements of `elementType` (e.g. int32_t). The span becomes data. Optional `format` (hex/decimal/character/unsignedDecimal/octal/binary/negativeHex) materializes each element's value in the listing.",
            mutates: true, arguments: ["address", "elementType", "count", "format"]) { arguments, store in
            let target = try address(arguments, "address")
            guard case let .int(count)? = arguments["count"], count > 0,
                  count <= Int64(DataShapeOverride.maxElementCount) else {
                throw ScriptingError.invalidArgument("count must be a positive integer <= \(DataShapeOverride.maxElementCount)")
            }
            var displayFormat: OperandFormat?
            if arguments["format"] != nil {
                let format = try string(arguments, "format")
                if !format.isEmpty {
                    guard let parsed = OperandFormat(rawValue: format) else {
                        throw ScriptingError.invalidArgument("format must be one of \(OperandFormat.allCases.map(\.rawValue).joined(separator: "|"))")
                    }
                    displayFormat = parsed
                }
            }
            let elementType: String?
            if arguments["elementType"] == nil {
                elementType = nil
            } else {
                elementType = try string(arguments, "elementType")
            }
            store.makeArray(target, in: store.snapshot.primarySlot, elementType: (elementType?.isEmpty == false) ? elementType : nil, count: Int(count), displayFormat: displayFormat)
            return .object(["ok": .bool(true), "address": .hex(target), "count": .int(count)])
        }
        add("make-alignments", "Mark 1–1024 primary-image alignment addresses in one undoable batch. Validates all entries before one structural reanalysis dispatch.", mutates: true, arguments: ["entries"]) { arguments, store in
            let values = try alignmentBatchEntries(arguments)
            let slot = store.snapshot.primarySlot
            let edits = try values.map { value in
                guard case let .int(boundary)? = value["boundary"] else {
                    throw ScriptingError.invalidArgument("boundary must be an integer")
                }
                return (address: try address(value, "address"), boundary: Int(boundary))
            }
            try Task.checkCancellation()
            return try ScriptingWriteReadback.overrideBatch(command: "make-alignments", store: store, slot: slot,
                expected: try edits.map { edit in
                    (edit.address, try ScriptingWriteReadback.dataShape(DataShapeOverride(kind: .alignment, alignment: edit.boundary)))
                },
                project: { (try? ScriptingWriteReadback.dataShape($0.dataShape)) ?? .null }) {
                let result = store.makeAlignmentsBatch(edits, in: slot)
                ScriptingBatchReceiptCapture.current?.record(.init(command: "make-alignments", count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
            }
        }
        add("make-alignment", "Mark an address in the primary image as alignment padding to a power-of-two byte boundary (2/4/8/16…; independent of the focused image).",
            mutates: true, arguments: ["address", "boundary"]) { arguments, store in
            let target = try address(arguments, "address")
            guard case let .int(boundary)? = arguments["boundary"], boundary > 1,
                  boundary <= Int64(DataShapeOverride.maxAlignment),
                  boundary & (boundary - 1) == 0 else {
                throw ScriptingError.invalidArgument("boundary must be a power of two (2, 4, 8, 16…) up to \(DataShapeOverride.maxAlignment)")
            }
            store.makeAlignment(target, in: store.snapshot.primarySlot, boundary: Int(boundary))
            return .object(["ok": .bool(true), "address": .hex(target), "boundary": .int(boundary)])
        }
        add("make-strings", "Mark 1–1024 primary-image string addresses in one undoable batch. Omitted length selects NUL termination; a positive integer selects a fixed length.", mutates: true, arguments: ["entries"]) { arguments, store in
            let values = try stringShapeBatchEntries(arguments)
            let slot = store.snapshot.primarySlot
            let edits = try values.map { value in
                let length: Int?
                if case let .int(number)? = value["length"] { length = Int(number) } else { length = nil }
                return (address: try address(value, "address"), length: length)
            }
            try Task.checkCancellation()
            return try ScriptingWriteReadback.overrideBatch(command: "make-strings", store: store, slot: slot,
                expected: try edits.map { edit in
                    (edit.address, try ScriptingWriteReadback.dataShape(edit.length.map {
                        DataShapeOverride(kind: .string, isNullTerminated: false, stringLength: $0)
                    } ?? DataShapeOverride(kind: .string, isNullTerminated: true)))
                },
                project: { (try? ScriptingWriteReadback.dataShape($0.dataShape)) ?? .null }) {
                let result = store.makeStringsBatch(edits, in: slot)
                ScriptingBatchReceiptCapture.current?.record(.init(command: "make-strings", count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
            }
        }
        add("make-string", "Mark an address in the primary image as a string: NUL-terminated C string (default) or fixed `length` bytes. The span becomes data (independent of the focused image).",
            mutates: true, arguments: ["address", "length"]) { arguments, store in
            let target = try address(arguments, "address")
            if let value = arguments["length"] {
                guard case .int(let length) = value, length > 0,
                      length <= Int64(DataShapeOverride.maxStringLength) else {
                    throw ScriptingError.invalidArgument("length must be a positive integer <= \(DataShapeOverride.maxStringLength)")
                }
                store.makeString(target, in: store.snapshot.primarySlot, length: Int(length))
                return .object(["ok": .bool(true), "address": .hex(target), "length": .int(length)])
            }
            store.makeString(target, in: store.snapshot.primarySlot, length: nil)
            return .object(["ok": .bool(true), "address": .hex(target), "nullTerminated": .bool(true)])
        }
        add("set-undefined", "Set 1–1024 primary-image undefined marks in one undoable batch. Omitted isUndefined defaults to true.", mutates: true, arguments: ["entries"]) { arguments, store in
            let values = try undefinedBatchEntries(arguments)
            let slot = store.snapshot.primarySlot
            let edits = try values.map { value in (address: try address(value, "address"), value: value["isUndefined"]?.boolValue ?? true) }
            try Task.checkCancellation()
            return try ScriptingWriteReadback.overrideBatch(command: "set-undefined", store: store, slot: slot,
                expected: edits.map { ($0.address, ScriptValue.bool($0.value)) },
                project: { .bool($0.isUndefined) }) {
                let result = store.setUndefinedBatch(edits, in: slot)
                ScriptingBatchReceiptCapture.current?.record(.init(command: "set-undefined", count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
            }
        }
        add("make-undefined", "Mark an address in the primary image as UNDEFINED (true) or defined (false) — removes it from code analysis and renders a raw .byte undefined directive. Re-drives the primary image's analysis (independent of the focused image).",
            mutates: true, arguments: ["address", "isUndefined"]) { arguments, store in
            let target = try address(arguments, "address")
            if let value = arguments["isUndefined"], value.boolValue == nil {
                throw ScriptingError.invalidArgument("isUndefined must be a boolean")
            }
            let isUndefined = arguments["isUndefined"]?.boolValue ?? true
            store.setMarkAsUndefined(target, in: store.snapshot.primarySlot, isUndefined)
            return .object(["ok": .bool(true), "address": .hex(target), "isUndefined": .bool(isUndefined)])
        }
        add("patch-bytes", "Overwrite the primary image bytes at an address, independent of the focused image, with hex `bytes` (e.g. '1f 20 03 d5'), or `nop`: true for a NOP. The listing re-decodes the patch. Re-drives analysis.",
            mutates: true, arguments: ["address", "bytes", "nop"]) { arguments, store in
            let target = try address(arguments, "address")
            if arguments["nop"]?.boolValue == true {
                guard store.patchNOP(target, in: store.snapshot.primarySlot),
                      let patch = store.snapshot.patches(in: store.snapshot.primarySlot)[target] else {
                    throw ScriptingError.invalidArgument(store.lastIssue ?? "The NOP patch could not be applied")
                }
                return committedPatchResult(target, patch: patch, diagnostic: store.lastIssue)
            }
            let hex = try string(arguments, "bytes")
            guard let patch = BytePatch.parse(hex: hex) else {
                throw ScriptingError.invalidArgument("bytes must be an even-length hex string (e.g. '1f 20 03 d5')")
            }
            guard store.setPatch(target, in: store.snapshot.primarySlot, patch) else {
                throw ScriptingError.invalidArgument(store.lastIssue ?? "The byte patch could not be applied")
            }
            return committedPatchResult(target, patch: patch, diagnostic: store.lastIssue)
        }
        add("clear-patch", "Remove a primary image byte patch at an address, independent of the focused image, restoring the original bytes.", mutates: true, arguments: ["address"]) { arguments, store in
            let target = try address(arguments, "address")
            store.clearPatch(target, in: store.snapshot.primarySlot)
            return .object(["ok": .bool(true), "address": .hex(target)])
        }
        add("append-code-cave", "Author or clear one ARM64 executable cave for a primary-image function. Supply its function entry, branch site and instruction bytes as hex. Save Patched Binary admits supported signed thin Mach-O layouts and the native decompiler follows the generated branch; unsupported layouts refuse without an output.",
            mutates: true, arguments: ["functionAddress", "branchAddress", "bytes", "clear"]) { arguments, store in
            let entry = try address(arguments, "functionAddress")
            let slot = store.snapshot.primarySlot
            let clearing = arguments["clear"]?.boolValue == true
            if clearing {
                guard store.clearAppendedExecutableCave(at: entry, in: slot) else {
                    throw ScriptingError.invalidArgument(store.lastIssue ?? "The appended cave could not be cleared")
                }
                return .object([
                    "ok": .bool(true), "functionAddress": .hex(entry),
                    "branchAddress": .hex(entry), "byteCount": .count(0)
                ])
            }
            guard let function = store.snapshot.analysis(in: slot)?.functions.first(where: {
                $0.startAddress == entry
            }) else {
                throw ScriptingError.invalidArgument("functionAddress must name a function entry in the primary image")
            }
            let branch = try address(arguments, "branchAddress")
            guard let parsed = BytePatch.parse(hex: try string(arguments, "bytes")) else {
                throw ScriptingError.invalidArgument("bytes must contain 1–4096 bytes of even-length instruction hex")
            }
            let bytes = Data(parsed.bytes)
            guard store.setAppendedExecutableCave(
                functionID: function.id, in: slot,
                branchSourceAddress: branch, codeBytes: bytes
            ) else {
                throw ScriptingError.invalidArgument(store.lastIssue ?? "The appended cave could not be authored")
            }
            return .object([
                "ok": .bool(true), "functionAddress": .hex(entry),
                "branchAddress": .hex(branch), "byteCount": .count(UInt64(bytes.count))
            ])
        }

        // --- Produce-executable: write the patched binary (wraps MachOPatchWriter) ---
        add("save-patched-binary", "Apply the primary image's byte patches to its CAPTURED thin Mach-O bytes (the image as loaded into this workspace, not the file now at its path), independent of the focused image, and write the result. Give a `path` to write to disk, or omit it to return the patched bytes base64-encoded. Surfaces MachOPatchWriter's typed errors (fat binary, unmapped/overrun patch, not-Mach-O). A changed signed executable is re-signed ad hoc in process (`signing: ad-hoc`, no team identity); `warnings` names entitlements an ad-hoc signature cannot honor. Otherwise the output is UNSIGNED (`unsigned: true`) — re-sign with `codesign -f -s - <path>` before running.",
            arguments: ["path"]) { arguments, store in
            // MS-15: derive the output from the primary image's CAPTURED bytes through the same
            // capture/prepare/recheck helper as the GUI, never from the file now at `binary.path`.
            let slot = store.snapshot.primarySlot
            let patchedData: Data
            let prepared: PreparedMachOPatchExport
            let capture: PatchedBinaryExportCapture
            do {
                capture = try store.capturePatchedBinaryExport(in: slot)
                prepared = try capture.prepare()
                patchedData = try store.finishPatchedBinaryExport(prepared, in: slot)
            } catch PatchedBinaryExportError.noImage {
                throw ScriptingError.invalidArgument("no binary is loaded to patch")
            } catch let error as LocalizedError {
                // Surface the writer's / preparation's exact, actionable message (same as the GUI path).
                throw ScriptingError.invalidArgument(error.errorDescription ?? "patch write failed")
            }
            if let path = arguments["path"]?.stringValue, !path.isEmpty {
                let destination = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
                do {
                    try capture.write(patchedData, to: destination)
                } catch {
                    throw ScriptingError.invalidArgument("could not write the patched binary to \(destination.lastPathComponent): \(error.localizedDescription)")
                }
                return .object([
                    "ok": .bool(true),
                    "path": .string(destination.path),
                    "patchCount": .int(Int64(prepared.patchCount)),
                    "byteCount": .count(UInt64(patchedData.count)),
                    "unsigned": .bool(Self.isUnsigned(prepared.signing)),
                    "signing": .string(Self.signingKind(prepared.signing)),
                    "warnings": .array(Self.signingWarnings(prepared.signing).map(ScriptValue.string)),
                    "note": .string(prepared.signing.summary),
                ])
            }
            return .object([
                "ok": .bool(true),
                "patchCount": .int(Int64(prepared.patchCount)),
                "byteCount": .count(UInt64(patchedData.count)),
                "unsigned": .bool(Self.isUnsigned(prepared.signing)),
                "signing": .string(Self.signingKind(prepared.signing)),
                "warnings": .array(Self.signingWarnings(prepared.signing).map(ScriptValue.string)),
                "bytesBase64": .string(patchedData.base64EncodedString()),
            ])
        }

        // --- Register renames in pseudocode (scoped to a procedure, undoable) ---
        add("rename-register", "Rename a REGISTER in the decompiled pseudocode for a primary-image function (by `function` display or raw name, or `address` inside it; independent of the focused image). `register` is the register id (e.g. x19); `name` is the display name. The rename shows at every occurrence of that register in the function's body and survives save/reopen + re-analysis. Cost: scans primary-image functions; a changed edit updates one procedure override with undo and may write an attached journal. Usually display-only; pruning empty legacy structural metadata may trigger reanalysis.",
            mutates: true, arguments: ["function", "address", "register", "name"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            let register = try string(arguments, "register")
            guard !register.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ScriptingError.invalidArgument("register must be a non-empty identifier (e.g. x19)")
            }
            let name = try string(arguments, "name")
            store.renameRegister(
                procedureStart: function.startAddress, in: store.snapshot.primarySlot,
                register: register, name: name
            )
            return functionReply(.object(["ok": .bool(true), "address": .hex(function.startAddress), "register": .string(register), "name": .string(name)]), arguments: arguments, function: function)
        }
        add("clear-register-name", "Clear a register rename for a primary-image function (by `function` display or raw name, or `address` inside it; independent of the focused image), restoring the raw register identifier in the pseudocode. Cost: scans primary-image functions; a changed edit updates one procedure override with undo and may write an attached journal. Usually display-only; pruning empty legacy structural metadata may trigger reanalysis.",
            mutates: true, arguments: ["function", "address", "register"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            let register = try string(arguments, "register")
            guard !register.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ScriptingError.invalidArgument("register must be a non-empty identifier (e.g. x19)")
            }
            store.renameRegister(
                procedureStart: function.startAddress, in: store.snapshot.primarySlot,
                register: register, name: nil
            )
            return functionReply(.object(["ok": .bool(true), "address": .hex(function.startAddress), "register": .string(register)]), arguments: arguments, function: function)
        }
        for (command, clearing) in [("rename-registers", false), ("clear-register-names", true)] {
            add(command, "Batch register name edits for primary-image functions (1–1024 entries). Resolves and validates all entries before a single undoable update; changed counts procedure override records. Empty names clear. Legacy structural metadata pruning may trigger reanalysis; reanalysisStatus reports this dispatch only.", mutates: true, arguments: ["entries"]) { arguments, store in
                let values = try registerBatchEntries(arguments, clearing: clearing)
                let snapshot = store.snapshot
                let slot = snapshot.primarySlot
                var seen: [UInt64: Set<String>] = [:]
                var edits: [(procedureStart: UInt64, register: String, name: String?)] = []
                for (index, value) in values.enumerated() {
                    let function = try resolveFunction(value, snapshot)
                    let register = try string(value, "register")
                    let normalized = register.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    guard seen[function.startAddress, default: []].insert(normalized).inserted else {
                        throw ScriptingError.invalidArgument("entries[\(index)]: duplicate resolved function/register pair")
                    }
                    edits.append((function.startAddress, register, clearing ? nil : value["name"]?.stringValue))
                }
                try Task.checkCancellation()
                let normalizedRegisters = edits.map { $0.register.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                return try ScriptingWriteReadback.batch(command: command, store: store, slot: slot,
                    rows: edits.enumerated().map { index, edit in
                        (["address": .hex(edit.procedureStart), "register": .string(normalizedRegisters[index])],
                         ScriptingWriteReadback.text(edit.name))
                    },
                    observe: { snapshot in
                        edits.enumerated().map { index, edit in
                            let names = snapshot.addressOverrides[ImageAddress(slot: slot, address: edit.procedureStart)]?.registerNames
                            return ScriptingWriteReadback.text(names?[normalizedRegisters[index]])
                        }
                    }) {
                    let outcome = store.renameRegistersBatch(edits, in: slot, actionName: clearing ? "Clear Register Names" : "Rename Registers")
                    ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(edits.count), changed: Int64(outcome.changed), imageSlot: Int64(slot.rawValue)))
                    return .object(["ok": .bool(true), "committed": .bool(outcome.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(outcome.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(outcome.reanalysisStatus)])
                }
            }
        }
        add("register-names", "List the register renames for a primary-image function (by `function` display or raw name, or `address` inside it) as {register: name} pairs.",
            arguments: ["function", "address"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            let names = store.snapshot.registerNameOverrides(forProcedureAt: function.startAddress)
            return functionReply(.object([
                "address": .hex(function.startAddress),
                "renames": .object(names.mapValues(ScriptValue.string)),
            ]), arguments: arguments, function: function)
        }

        // --- DP04 C1: stack local names/types (scoped to a procedure, undoable) ---
        add("set-stack-local", "Rename and/or retype a STACK LOCAL in the decompiled pseudocode for a primary-image function (by `function` display or raw name, or `address` inside it). `local` is the local's entry-SP byte range `lo:hi` (e.g. -24:-16, as `stack-locals` reports it). `name` sets the name and `type` the C type; an empty value clears that field, an omitted one keeps it. The edit survives save/reopen and re-analysis; a range that no longer matches a local is kept as an orphan. Cost: scans primary-image functions; a changed edit updates one procedure override with undo and may write an attached journal. Usually display-only; pruning empty legacy structural metadata may trigger reanalysis.",
            mutates: true, arguments: ["function", "address", "local", "name", "type"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            let local = try string(arguments, "local")
            guard let range = MacIRStackStorage.entryRange(forAuthoringKey: local) else {
                throw ScriptingError.invalidArgument("local must be an entry-SP byte range lo:hi (e.g. -24:-16)")
            }
            let name = arguments["name"]?.stringValue
            let type = arguments["type"]?.stringValue
            guard name != nil || type != nil else { throw ScriptingError.invalidArgument("provide name and/or type") }
            if let name, !name.isEmpty, !PseudocodePrinter.isCIdentifier(name) {
                throw ScriptingError.invalidArgument("name must be a C identifier")
            }
            if let type, !type.isEmpty, !PseudocodePrinter.isTypeSpelling(type) {
                throw ScriptingError.invalidArgument("type must be a C type spelling (identifiers and trailing *)")
            }
            for field in ["name", "type"] {
                if let value = arguments[field], value != .null, value.stringValue == nil {
                    throw ScriptingError.invalidArgument("\(field) must be a string")
                }
            }
            store.editStackLocal(procedureStart: function.startAddress, in: store.snapshot.primarySlot,
                                 entryRange: range, name: name, typeName: type)
            let stored = store.snapshot.stackLocalOverrides(forProcedureAt: function.startAddress, in: store.snapshot.primarySlot)[local]
            return functionReply(.object([
                "ok": .bool(true), "address": .hex(function.startAddress), "local": .string(local),
                "name": stored?.name.map(ScriptValue.string) ?? .null,
                "type": stored?.typeName.map(ScriptValue.string) ?? .null,
            ]), arguments: arguments, function: function)
        }
        add("set-stack-locals", "Edit stack-local names and types for primary-image functions (1–1024 entries). Validates every edit before one undoable update; changed counts procedure overrides. Legacy structural metadata pruning may trigger reanalysis.", mutates: true, arguments: ["entries"]) { arguments, store in
            let entries = try stackLocalBatchEntries(arguments)
            let snapshot = store.snapshot
            let slot = snapshot.primarySlot
            var seen: [UInt64: Set<String>] = [:]
            var edits: [(procedureStart: UInt64, entryRange: Range<Int64>, name: String?, typeName: String?)] = []
            for (index, entry) in entries.enumerated() {
                let function = try resolveFunction(entry, snapshot)
                let local = try string(entry, "local")
                guard let range = MacIRStackStorage.entryRange(forAuthoringKey: local) else {
                    throw ScriptingError.invalidArgument("local must be an entry-SP byte range lo:hi (e.g. -24:-16)")
                }
                let name = entry["name"]?.stringValue
                let type = entry["type"]?.stringValue
                guard name != nil || type != nil else { throw ScriptingError.invalidArgument("provide name and/or type") }
                if let name, !name.isEmpty, !PseudocodePrinter.isCIdentifier(name) {
                    throw ScriptingError.invalidArgument("name must be a C identifier")
                }
                if let type, !type.isEmpty, !PseudocodePrinter.isTypeSpelling(type) {
                    throw ScriptingError.invalidArgument("type must be a C type spelling (identifiers and trailing *)")
                }
                for field in ["name", "type"] {
                    if let value = entry[field], value != .null, value.stringValue == nil {
                        throw ScriptingError.invalidArgument("\(field) must be a string")
                    }
                }
                let canonical = MacIRStackStorage.authoringKey(for: range)
                guard seen[function.startAddress, default: []].insert(canonical).inserted else {
                    throw ScriptingError.invalidArgument("entries[\(index)]: duplicate resolved function/local pair")
                }
                edits.append((function.startAddress, range, name, type))
            }
            try Task.checkCancellation()
            // Requested state is the merge of the current local with the supplied fields
            // (an omitted field is left unchanged, an empty one clears), as the store applies it.
            @MainActor func localState(_ local: StackLocalOverride?) -> ScriptValue {
                let value = local?.normalized
                return .object(["name": ScriptingWriteReadback.text(value?.name),
                                "type": ScriptingWriteReadback.text(value?.typeName)])
            }
            let keys = edits.map { MacIRStackStorage.authoringKey(for: $0.entryRange) }
            return try ScriptingWriteReadback.batch(command: "set-stack-locals", store: store, slot: slot,
                rows: edits.enumerated().map { index, edit in
                    let current = snapshot.addressOverrides[ImageAddress(slot: slot, address: edit.procedureStart)]?.stackLocals?[keys[index]]
                    var merged = current ?? StackLocalOverride()
                    if let name = edit.name { merged.name = WorkspaceStore.normalizedOverrideText(name) }
                    if let type = edit.typeName { merged.typeName = WorkspaceStore.normalizedOverrideText(type) }
                    return (["address": .hex(edit.procedureStart), "local": .string(keys[index])], localState(merged))
                },
                observe: { after in
                    edits.enumerated().map { index, edit in
                        localState(after.addressOverrides[ImageAddress(slot: slot, address: edit.procedureStart)]?.stackLocals?[keys[index]])
                    }
                }) {
                let result = store.editStackLocalsBatch(edits, in: slot)
                ScriptingBatchReceiptCapture.current?.record(.init(command: "set-stack-locals", count: Int64(edits.count), changed: Int64(result.changed), imageSlot: Int64(slot.rawValue)))
                return .object(["ok": .bool(true), "committed": .bool(result.changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(result.changed)), "imageSlot": .int(Int64(slot.rawValue)), "reanalysisStatus": .string(result.reanalysisStatus)])
            }
        }
        add("stack-locals", "List a primary-image function's recovered stack locals (by `function` display or raw name, or `address` inside it) keyed by entry-SP range `lo:hi`, its stack local edits with `orphan: true` for an edit whose range matches no recovered local, and its register renames (`registers`) with `orphan: true` for a register the function never references.",
            arguments: ["function", "address"]) { arguments, store in
            let snapshot = store.snapshot
            let slot = snapshot.primarySlot
            let function = try resolveFunction(arguments, snapshot)
            let edits = snapshot.stackLocalOverrides(forProcedureAt: function.startAddress, in: slot)
            let irFunction = PseudocodePrinter().buildFunction(
                functionName: snapshot.displayName(at: function.startAddress, in: slot, default: function.name),
                startAddress: function.startAddress,
                jumpTables: snapshot.resolvedJumpTables(in: slot),
                objcSelectors: snapshot.analysis(in: slot)?.objcSelectors ?? [:],
                constantStrings: snapshot.constantStrings(in: slot),
                signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
                authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
                types: snapshot.typeDefinitions,
                instructions: snapshot.pseudocodeTarget(selectedAddress: function.startAddress, in: slot)?.instructions ?? []
            )
            var recovered: [String: ScriptValue] = [:]
            for local in irFunction.localVariables {
                guard let storage = local.stackStorage else { continue }
                recovered[storage.authoringKey] = .object([
                    "name": .string(local.name), "type": .string(local.type),
                    "role": .string(storage.role.rawValue), "escapes": .bool(storage.escapes),
                ])
            }
            // A register rename applies to every occurrence (x and w views); it is an orphan
            // when the function's rows never name that register.
            var referenced = Set<String>()
            for row in irFunction.instructions {
                for token in row.source.operands.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }) {
                    guard let first = token.first, first == "x" || first == "w",
                          let index = Int(token.dropFirst()), (0...30).contains(index) else { continue }
                    referenced.insert("x\(index)")
                }
            }
            let registerNames = snapshot.registerNameOverrides(forProcedureAt: function.startAddress, in: slot)
            return functionReply(.object([
                "address": .hex(function.startAddress),
                "recovered": .object(recovered),
                "registers": .object(registerNames.reduce(into: [:]) { result, entry in
                    let key = entry.key.hasPrefix("w") ? "x" + entry.key.dropFirst() : entry.key
                    result[entry.key] = .object(["name": .string(entry.value), "orphan": .bool(!referenced.contains(key))])
                }),
                "edits": .object(edits.reduce(into: [:]) { result, entry in
                    result[entry.key] = .object([
                        "name": entry.value.name.map(ScriptValue.string) ?? .null,
                        "type": entry.value.typeName.map(ScriptValue.string) ?? .null,
                        "orphan": .bool(recovered[entry.key] == nil),
                    ])
                }),
            ]), arguments: arguments, function: function)
        }

        // --- DP04 D2: struct recovery from usage (read-only candidate, explicit acceptance) ---
        add("recover-struct-candidate", "Read-only: the usage-derived layout candidate for parameter `parameter` (GPR index, x0 = 0) of a primary-image function (by `function` display or raw name, or `address` inside it): fields by offset/width with evidence addresses, overlap conflicts, unknown gaps, the extent lower bound, whether the root is an interior pointer, unresolved accesses and incomplete reasons. Direct callees receiving root + k contribute (bounded). Nothing is mutated; `candidate` is the id `accept-struct-candidate` checks.",
            arguments: ["function", "address", "parameter"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            let parameter = try Self.structCandidateParameter(arguments)
            let candidate = Self.structCandidate(snapshot: store.snapshot, function: function, parameter: parameter)
            return functionReply(Self.scriptValue(candidate), arguments: arguments, function: function)
        }
        add("accept-struct-candidate", "Accept a struct candidate from `recover-struct-candidate` as a new catalog type `name` (undoable, one step). `candidate` must equal the id the current analysis produces (stale evidence is rejected). Each overlap needs one entry in `choices` [{offset, width}]. The type is packed with explicit `_unknown_0x…` byte members for unobserved bytes, so every observed offset is reproduced exactly; an interior-pointer root is refused. `local` (entry-SP range `lo:hi`) optionally types that stack local as `name *`.",
            mutates: true, arguments: ["function", "address", "parameter", "candidate", "name", "choices", "local"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            let parameter = try Self.structCandidateParameter(arguments)
            let expected = try string(arguments, "candidate")
            let name = try string(arguments, "name")
            let candidate = Self.structCandidate(snapshot: store.snapshot, function: function, parameter: parameter)
            guard candidate.candidateID == expected else {
                throw ScriptingError.invalidArgument("the candidate is stale: recover it again (current \(candidate.candidateID))")
            }
            var choices: [StructCandidateTypeAdapter.Choice] = []
            if let value = arguments["choices"] {
                guard let list = value.arrayValue else {
                    throw ScriptingError.invalidArgument("choices must be an array")
                }
                for element in list {
                    guard let choice = Self.exactStructChoice(element) else {
                        throw ScriptingError.invalidArgument("each choice needs an integer offset and width")
                    }
                    choices.append(choice)
                }
            }
            var local: (procedureStart: UInt64, imageSlot: ImageSlot, entryRange: Range<Int64>)?
            if let value = arguments["local"] {
                guard let key = value.stringValue,
                      let range = MacIRStackStorage.entryRange(forAuthoringKey: key) else {
                    throw ScriptingError.invalidArgument("local must be an entry-SP byte range lo:hi")
                }
                local = (function.startAddress, store.snapshot.primarySlot, range)
            }
            let definition: TypeDefinition
            do {
                definition = try StructCandidateTypeAdapter.typeDefinition(
                    for: candidate, name: name, choices: choices, existing: store.snapshot.typeDefinitions)
            } catch let refusal as StructCandidateTypeAdapter.Refusal {
                throw ScriptingError.invalidArgument(Self.refusalText(refusal))
            }
            store.acceptStructCandidate(definition, assigningStackLocal: local)
            return functionReply(.object([
                "ok": .bool(true), "name": .string(name), "candidate": .string(expected),
                "fields": .array(definition.fields.map { .object(["name": .string($0.name), "type": .string($0.type)]) }),
                "local": local.map { .string(MacIRStackStorage.authoringKey(for: $0.entryRange)) } ?? .null,
            ]), arguments: arguments, function: function)
        }

        add("indirect-call-targets", "Read-only: for a primary-image function (by `function` display or raw name, or `address` inside it), each indirect call through a memory slot (`ldr xN, [obj, #off]; blr xN`) that resolves to exactly one function: function-local when the single store reaches the load in one block, or signature-typed when the root parameter's declared type names a struct and image-wide exactly one function is stored to that slot. Refused calls carry a reason (noSlot, noStore, multipleValues, poisoned, notDominating). Indexed and multi-target slots are never guessed.",
            arguments: ["function", "address"]) { arguments, store in
            let function = try resolveFunction(arguments, store.snapshot)
            return functionReply(Self.indirectCallTargets(snapshot: store.snapshot, function: function), arguments: arguments, function: function)
        }

        add("verified-checkpoint", "Read-only (group: verified analysis): judge the live workspace against an `expectation` (operation IDs plus expected fields; the shape the headless verified-checkpoint action decodes) with the saved-bytes checkpoint reader. Returns per-operation outcome codes, package findings, unexpected operation IDs and the bounds. Optional `imageSlot` refuses an expectation naming another slot. Oversize or malformed expectations are typed refusals. Mutates nothing and records no undo step. Every reply says process: same, so it is never the fresh-process proof, and carries the analysis generation.", arguments: ["expectation", "imageSlot"]) { arguments, store in try Self.verifiedCheckpointReply(arguments, store: store) }

        // --- Per-procedure local labels (undoable) ---
        add("set-local-label", "Set a LOCAL LABEL (a function-scoped name) at an address in the primary image (the image `local-labels` reads; independent of the focused image) — rendered in the listing/pseudocode within the enclosing function. Empty `label` clears it. Distinct from `rename` (a global symbol name). Cost: at most one override commit and one undo step per call; remaining observer work grows with image size.",
            mutates: true, arguments: ["address", "label"]) { arguments, store in
            let target = try address(arguments, "address")
            let label = try string(arguments, "label")
            let slot = store.snapshot.primarySlot
            return try ScriptingWriteReadback.overrides(command: "set-local-label", store: store, slot: slot,
                field: .label, expected: [(target, ScriptingWriteReadback.text(label))]) {
                    store.setLocalLabel(target, in: slot, label: label.isEmpty ? nil : label)
                    return .object(["ok": .bool(true), "address": .hex(target), "label": .string(label)])
                }
        }
        add("clear-local-label", "Clear the local label at an address in the primary image (independent of the focused image). Cost: at most one override commit and one undo step per call; remaining observer work grows with image size.", mutates: true, arguments: ["address"]) { arguments, store in
            let target = try address(arguments, "address")
            let slot = store.snapshot.primarySlot
            return try ScriptingWriteReadback.overrides(command: "clear-local-label", store: store, slot: slot,
                field: .label, expected: [(target, .null)]) {
                    store.setLocalLabel(target, in: slot, label: nil)
                    return .object(["ok": .bool(true), "address": .hex(target)])
                }
        }
        add("local-labels", "List the primary image's user local labels (address -> label).") { _, store in
            .array(store.snapshot.localLabels(in: store.snapshot.primarySlot).sorted { $0.key < $1.key }.map { address, label in
                .object(["address": .hex(address), "label": .string(label)])
            })
        }

        // --- Manual cross-references (add / suppress, undoable) ---
        // Like `rename`, these bind to the primary image — the image `xrefs` reads (its
        // effective xrefs merge only same-image edits) — never to live focus.
        add("add-xref", "Add a cross-reference the recovery missed in the primary image (the image `xrefs` reads; independent of the focused image): `from` -> `to`, with `kind` (call|string|selref|classref|data, default call).",
            mutates: true, arguments: ["from", "to", "kind"]) { arguments, store in
            let from = try address(arguments, "from")
            let to = try address(arguments, "to")
            let kind = try manualXRefKind(arguments)
            store.addManualXRef(from: from, to: to, kind: kind, in: store.snapshot.primarySlot)
            return .object(["ok": .bool(true), "from": .hex(from), "to": .hex(to), "kind": .string(kind)])
        }
        add("suppress-xref", "Suppress a spurious recovered cross-reference in the primary image (independent of the focused image): `from` -> `to`, with `kind` (default call).",
            mutates: true, arguments: ["from", "to", "kind"]) { arguments, store in
            let from = try address(arguments, "from")
            let to = try address(arguments, "to")
            let kind = try manualXRefKind(arguments)
            store.suppressXRef(from: from, to: to, kind: kind, in: store.snapshot.primarySlot)
            return .object(["ok": .bool(true), "from": .hex(from), "to": .hex(to), "kind": .string(kind)])
        }
        for (command, suppressing) in [("add-xrefs", false), ("suppress-xrefs", true)] {
            add(command, "Add or suppress 1–1024 primary-image cross-references in one undoable operation. All entries are validated before mutation; duplicates are no-ops.", mutates: true, arguments: ["entries"]) { arguments, store in
                let values = try manualXRefBatchEntries(arguments)
                let slot = store.snapshot.primarySlot
                let entries = try values.map { entry in
                    (from: try address(entry, "from"), to: try address(entry, "to"), kind: try manualXRefKind(entry))
                }
                try Task.checkCancellation()
                // Requested: each endpoint is an edit of the batch's polarity afterwards. The
                // separate read is the manual-xref list, not the mutator's changed count.
                return try ScriptingWriteReadback.batch(command: command, store: store, slot: slot,
                    rows: entries.map { (["from": .hex($0.from), "to": .hex($0.to), "kind": .string($0.kind)],
                                         ScriptValue.string(suppressing ? "suppressed" : "added")) },
                    observe: { snapshot in
                        entries.map { entry in
                            let edit = snapshot.manualXRefs.first {
                                $0.imageSlot == slot && $0.from == entry.from && $0.to == entry.to && $0.kind == entry.kind
                            }
                            return edit.map { ScriptValue.string($0.isSuppression ? "suppressed" : "added") } ?? .null
                        }
                    }) {
                    let changed = store.editManualXRefsBatch(entries, in: slot, suppressing: suppressing)
                    ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(entries.count), changed: Int64(changed), imageSlot: Int64(slot.rawValue)))
                    return .object(["ok": .bool(true), "committed": .bool(changed > 0), "count": .int(Int64(entries.count)), "changed": .int(Int64(changed)), "imageSlot": .int(Int64(slot.rawValue))])
                }
            }
        }
        add("manual-xrefs", "List the primary image's user cross-reference edits (added/suppressed).") { _, store in
            let primarySlot = store.snapshot.primarySlot
            return .array(store.snapshot.manualXRefs.filter { $0.imageSlot == primarySlot }.map { edit in
                .object([
                    "from": .hex(edit.from),
                    "to": .hex(edit.to),
                    "kind": .string(edit.kind),
                    "suppressed": .bool(edit.isSuppression),
                ])
            })
        }

        // --- Bookmarks (undoable) ---
        add("add-bookmark", "Add (or rename) a named bookmark at an address in the primary image (the image `bookmarks` lists; independent of the focused image).", mutates: true, arguments: ["address", "name"]) { arguments, store in
            let target = try address(arguments, "address")
            if let value = arguments["name"], value != .null, value.stringValue == nil {
                throw ScriptingError.invalidArgument("name must be a string")
            }
            let name = arguments["name"]?.stringValue ?? ""
            let slot = store.snapshot.primarySlot
            return try ScriptingWriteReadback.bookmarks(command: "add-bookmark", store: store, slot: slot,
                expected: [(target, name)]) {
                    store.addBookmark(at: target, in: slot, name: name)
                    return .object(["ok": .bool(true), "address": .hex(target), "name": .string(name)])
                }
        }
        add("remove-bookmark", "Remove the bookmark at an address in the primary image (independent of the focused image).", mutates: true, arguments: ["address"]) { arguments, store in
            let target = try address(arguments, "address")
            let slot = store.snapshot.primarySlot
            return try ScriptingWriteReadback.bookmarks(command: "remove-bookmark", store: store, slot: slot,
                expected: [(target, nil)]) {
                    store.removeBookmark(at: target, in: slot)
                    return .object(["ok": .bool(true), "address": .hex(target)])
                }
        }
        for (command, removing) in [("add-bookmarks", false), ("remove-bookmarks", true)] {
            add(command, "Edit 1–1024 primary-image bookmarks as one undoable operation. All entries are validated before mutation; repeated addresses are processed in order.", mutates: true, arguments: ["entries"]) { arguments, store in
                let values = try bookmarkBatchEntries(arguments, removing: removing)
                let slot = store.snapshot.primarySlot
                let entries = try values.map { entry in
                    (address: try address(entry, "address"), name: removing ? nil : (entry["name"]?.stringValue ?? ""))
                }
                try Task.checkCancellation()
                return try ScriptingWriteReadback.bookmarks(command: command, store: store, slot: slot,
                    expected: entries.map { ($0.address, $0.name) }) {
                        let changed = store.editBookmarksBatch(entries, in: slot, removing: removing)
                        ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(entries.count), changed: Int64(changed), imageSlot: Int64(slot.rawValue)))
                        return .object(["ok": .bool(true), "committed": .bool(changed > 0), "count": .int(Int64(entries.count)), "changed": .int(Int64(changed)), "imageSlot": .int(Int64(slot.rawValue))])
                    }
            }
        }
        add("bookmarks", "List the primary image's navigation bookmarks (address-sorted).") { _, store in
            let primarySlot = store.snapshot.primarySlot
            return .array(store.snapshot.sortedBookmarks().filter { $0.imageSlot == primarySlot }.map { bookmark in
                .object(["address": .hex(bookmark.address), "name": .string(bookmark.name)])
            })
        }

        // --- Segment / section display overrides (rename + rebase) ---
        add("rename-segment", "Rename a segment/section's displayed name (empty `name` clears the rename). Keys on the section's ORIGINAL `section` name.",
            mutates: true, arguments: ["section", "name"]) { arguments, store in
            let sectionName = try string(arguments, "section")
            if let value = arguments["name"], value != .null, value.stringValue == nil {
                throw ScriptingError.invalidArgument("name must be a string")
            }
            let name = arguments["name"]?.stringValue ?? ""
            store.renameSegment(sectionName: sectionName, displayName: name)
            return .object(["ok": .bool(true), "section": .string(sectionName), "name": .string(name)])
        }
        add("rebase-segment", "Shift a section's DISPLAYED addresses by a signed `delta` byte offset (0 clears the rebase). Analysis is untouched. Keys on the ORIGINAL `section` name. `delta` accepts a (possibly negative) integer or a hex string ('0x1000', '-0x1000').",
            mutates: true, arguments: ["section", "delta"]) { arguments, store in
            let sectionName = try string(arguments, "section")
            guard let deltaValue = arguments["delta"], let delta = signedDelta(deltaValue) else {
                throw ScriptingError.invalidArgument("delta must be an integer or hex string")
            }
            store.rebaseSegment(sectionName: sectionName, delta: delta)
            return .object(["ok": .bool(true), "section": .string(sectionName), "delta": .int(delta)])
        }
        for (command, rebasing) in [("rename-segments", false), ("rebase-segments", true)] {
            add(command, "Edit 1–1024 original sections in the focused image in one undoable batch. All entries and section names are validated before mutation.", mutates: true, arguments: ["entries"]) { arguments, store in
                let values = try segmentEditBatchEntries(arguments, rebasing: rebasing)
                let slot = store.focusedImageSlot
                let sections = Set(store.snapshot.analysis(in: slot)?.sections.map(\.name) ?? [])
                var edits: [(section: String, name: String?, delta: Int64?)] = []
                for (index, value) in values.enumerated() {
                    let section = try string(value, "section")
                    guard sections.contains(section) else { throw ScriptingError.invalidArgument("entries[\(index)].section: no such section") }
                    edits.append((section, rebasing ? nil : (value["name"]?.stringValue ?? ""), rebasing ? value["delta"].flatMap(signedDelta) : nil))
                }
                try Task.checkCancellation()
                // A repeated section is last-write-wins; each row compares the final state.
                @MainActor func requestedValue(_ edit: (section: String, name: String?, delta: Int64?)) -> ScriptValue {
                    rebasing ? .int(edit.delta ?? 0)
                        : ScriptingWriteReadback.text(edit.name)
                }
                var finalRequested: [String: ScriptValue] = [:]
                for edit in edits { finalRequested[edit.section] = requestedValue(edit) }
                return try ScriptingWriteReadback.batch(command: command, store: store, slot: slot,
                    rows: edits.map { (["section": .string($0.section)], finalRequested[$0.section] ?? requestedValue($0)) },
                    observe: { snapshot in
                        edits.map { edit in
                            let override = snapshot.segmentOverrides.first { $0.imageSlot == slot && $0.originalName == edit.section }
                            return rebasing ? .int(override?.rebaseDelta ?? 0)
                                : ScriptingWriteReadback.text(override?.displayName)
                        }
                    }) {
                    let changed = store.editSegmentOverridesBatch(edits, in: slot, rebasing: rebasing)
                    ScriptingBatchReceiptCapture.current?.record(.init(command: command, count: Int64(edits.count), changed: Int64(changed), imageSlot: Int64(slot.rawValue)))
                    return .object(["ok": .bool(true), "committed": .bool(changed > 0), "count": .int(Int64(edits.count)), "changed": .int(Int64(changed)), "imageSlot": .int(Int64(slot.rawValue))])
                }
            }
        }
        add("clear-segment-override", "Remove the rename + rebase on a section.", mutates: true, arguments: ["section"]) { arguments, store in
            let sectionName = try string(arguments, "section")
            store.clearSegmentOverride(sectionName: sectionName)
            return .object(["ok": .bool(true), "section": .string(sectionName)])
        }
        add("clear-segment-overrides", "Clear rename and rebase overrides for up to 1024 original section names in the focused image, in one undoable batch.", mutates: true, arguments: ["entries"]) { arguments, store in
            let names = try clearSegmentOverrideEntries(arguments)
            let slot = store.focusedImageSlot
            return try ScriptingWriteReadback.batch(command: "clear-segment-overrides", store: store, slot: slot,
                rows: names.map { (["section": .string($0)], ScriptValue.string("cleared")) },
                observe: { snapshot in
                    names.map { name in
                        snapshot.segmentOverrides.contains { $0.imageSlot == slot && $0.originalName == name }
                            ? ScriptValue.string("present") : ScriptValue.string("cleared")
                    }
                }) {
                let changed = store.clearSegmentOverrides(sectionNames: names, in: slot)
                ScriptingBatchReceiptCapture.current?.record(.init(command: "clear-segment-overrides", count: Int64(names.count),
                                                                    changed: Int64(changed), imageSlot: Int64(slot.rawValue)))
                return .object(["ok": .bool(true), "committed": .bool(changed > 0),
                                "imageSlot": .int(Int64(slot.rawValue)), "count": .int(Int64(names.count)),
                                "changed": .int(Int64(changed))])
            }
        }
        add("segment-overrides", "List the user segment/section display overrides (rename + rebase).") { _, store in
            .array(store.snapshot.segmentOverrides.sorted { $0.originalName < $1.originalName }.map { override in
                .object([
                    "section": .string(override.originalName),
                    "displayName": override.displayName.map(ScriptValue.string) ?? .null,
                    "rebaseDelta": .int(override.rebaseDelta),
                ])
            })
        }

        // --- Type catalog ---
        add("list-types", "List the user-defined type catalog.") { arguments, store in
            try snapshotTypeListRead("list-types", arguments: arguments,
                snapshot: store.snapshot, checkpoint: {}, swiftObjCLinks: true, mode: .publicPrefix)
        }
        add("list-image-types", "RX-02a Type Atlas (read-only): the types of one image — Objective-C classes, categories and protocols (name only), Swift classes/structs/enums, and the workspace user types — with members (offset + evidence: descriptor|staticEvaluation|authored|unknown; an unknown layout has a null offset), conformances, methods (selector, IMP, selref users) and users (classref xref sources, or addresses a user type is applied to). Reads the primary image by default; `image` (a slot index or an image-owner ID) selects another loaded image. Optional `kind` filters (swiftClass|swiftStruct|swiftEnum|objcClass|objcCategory|objcProtocol|userType); optional `limit` caps the rows. The default reply (including an explicit `limit` and `page: false`) is a bounded prefix of full rows with a byte allowance C = 166,000: `total` is the whole-filter total and `types.count` the admitted prefix; unnamed positional Swift vtable slots may be replaced by `unnamedVtableSlots` {count, first, last} with `vtableSummaryVersion: 1`; when rows are omitted the reply carries `isTruncated: true` and `nextCursor`, which is continued as `cursor` with `page: true`, `fields: \"full\"`, `limit: 1` and the original image/kind. The complete frame is guaranteed within 180,000 bytes only for an encoded JSON request-id length I <= 13,000, since C + I + 1,000 <= 180,000; larger IDs are not clipped and have no such guarantee. Small replies keep their original shape. For Swift rows, `hasUnassignedSwiftConformanceRecords` reports whether recovered records in the image lack a unique local owner; false does not certify extraction completeness. The result carries `imageSlot`, `imageOwner`, `total` and `types`. `page: true` returns {rows, total, isTruncated, nextCursor, sourceComplete, imageSlot, imageOwner}; `cursor` continues from `nextCursor`, `name` / `nameContains` filter by name, and `fields: \"names\"` returns names-only rows. A non-null `name`, `nameContains` or `fields` without `page` also returns a page.",
            arguments: [imageSelectorArgument, "kind", "limit", "page", "cursor", "name", "nameContains", "fields", "format"]) { arguments, store in
            try snapshotTypeListRead("list-image-types", arguments: arguments,
                snapshot: store.snapshot, checkpoint: {}, swiftObjCLinks: true, mode: .publicPrefix)
        }
        add("define-type", "Add/update a type — kind: struct|union|enum|typedef, plus fields[] of {name, type}.",
            mutates: true, arguments: ["kind", "name", "fields"]) { arguments, store in
            let name = try string(arguments, "name")
            // True upsert BY NAME: reuse an existing same-named type's id so a repeat
            // call updates in place (the catalog enforces UNIQUE names, like the UI's
            // editor) instead of appending a duplicate that collapses on save. An omitted
            // kind or fields keeps the existing value: updating only `kind` must not erase
            // a struct's fields.
            let existing = store.snapshot.typeDefinitions.first(where: { $0.name == name })
            let rich = existing.map { definition in
                definition.layoutRules != .default || definition.vectorByteSize != nil
                    || definition.enumValuesIncomplete != nil || definition.fields.contains { field in
                    field.bitWidth != nil || field.bitOffset != nil || field.isPacked != nil
                        || field.layoutIsUnknown != nil || field.isAtomic != nil
                        || field.minimumAlignment != nil || field.minimumAlignmentType != nil
                        || field.inlineAggregateKind != nil || !field.inlineFields.isEmpty
                        || field.inlineAggregateLayoutRules != .default || field.promotesInlineFields
                        || (field.declaratorSemanticsV1 != nil && field.declaratorSemanticsV1 != .ordinary)
                }
            } ?? false
            let kind: TypeKind
            switch arguments["kind"] {
            case .none, .some(.null):
                kind = existing?.kind ?? .struct
            case .some(let value):
                guard let parsed = value.stringValue.flatMap(TypeKind.init(rawValue:)) else {
                    throw ScriptingError.invalidArgument("kind must be struct|union|enum|typedef")
                }
                kind = parsed
            }
            var fields: [FieldDef]
            switch arguments["fields"] {
            case .none, .some(.null):
                fields = existing?.fields ?? []
            case .some(let value):
                guard let elements = value.arrayValue else {
                    throw ScriptingError.invalidArgument("fields must be an array of {name, type}")
                }
                fields = try elements.map { element in
                    guard let fieldName = element["name"]?.stringValue, !fieldName.isEmpty,
                          let fieldType = element["type"]?.stringValue, !fieldType.isEmpty else {
                        throw ScriptingError.invalidArgument("each field needs a string name and type")
                    }
                    return FieldDef(name: fieldName, type: fieldType)
                }
            }
            if let existing, rich {
                guard kind == existing.kind,
                      fields.count == existing.fields.count,
                      zip(fields, existing.fields).allSatisfy({ pair in
                          pair.0.name == pair.1.name && pair.0.type == pair.1.type
                      }) else {
                    throw ScriptingError.invalidArgument("Unsupported lossy replacement of a rich type definition")
                }
                // Plain input may acknowledge identical leaves; it cannot erase richer storage authority.
                fields = existing.fields
            }
            let id = existing?.id ?? UUID()
            let definition = TypeDefinition(id: id, kind: kind, name: name, fields: fields,
                layoutRules: existing?.layoutRules ?? .default,
                vectorByteSize: existing?.vectorByteSize,
                enumValuesIncomplete: existing?.enumValuesIncomplete,
                // An accepted inferred layout keeps its evidence record only while its fields
                // are unchanged; an edited layout is fully authored.
                inferenceProvenance: existing.flatMap { $0.fields == fields ? $0.inferenceProvenance : nil })
            return try ScriptingWriteReadback.run(command: "define-type", store: store, slot: nil,
                requested: ScriptingWriteReadback.catalog(definition), read: { snapshot in
                    guard let stored = snapshot.typeDefinitions.first(where: { $0.id == id }) else { return .null }
                    return ScriptingWriteReadback.catalog(stored)
                }, matchesFullModel: { snapshot in
                    snapshot.typeDefinitions.first(where: { $0.id == id }) == definition
                }) {
                    store.upsertTypeDefinition(definition)
                    return .object(["ok": .bool(true), "name": .string(name)])
                }
        }
        add("define-types-from-c", "Parse pasted C source (`source`) — struct/union/enum/typedef declarations — and add the recovered types to the catalog (undoable). Names that already exist or can't be parsed are skipped with a diagnostic, never overwritten.",
            mutates: true, arguments: ["source"]) { arguments, store in
            let source = try string(arguments, "source")
            let summary = store.defineTypesFromCHeader(source)
            return .object([
                "ok": .bool(true),
                "added": .array(summary.addedNames.map { .string($0) }),
                "diagnostics": .array(summary.diagnostics.map { .string($0) }),
            ])
        }

        // --- Debug symbols (dSYM) import ---
        add("read-debug-symbols", "Read a .dSYM bundle (or bare DWARF Mach-O) at `path` and inject its recovered, demangled function names as name overrides on the loaded binary (undoable). The dSYM's LC_UUID must match the loaded binary; pass an `uuid` to override the expected UUID (otherwise the loaded binary's UUID is used), but a dSYM whose UUID differs from the binary's own LC_UUID is always refused (imageUUIDMismatch). Surfaces the importer's typed failures (uuidMismatch / notMachO / dwarfBinaryNotFound / noFunctionsRecovered / …) as errors.",
            mutates: true, arguments: ["path", "uuid"]) { arguments, store in
            let path = try string(arguments, "path")
            guard !path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ScriptingError.invalidArgument("path must be a non-empty path to a .dSYM bundle or DWARF Mach-O")
            }
            guard let binary = store.snapshot.binaries.first else {
                throw ScriptingError.invalidArgument("open a binary before reading its debug symbols")
            }
            // An explicit `uuid` argument overrides the loaded binary's UUID (lets a caller
            // verify against a UUID they already trust); otherwise the loaded binary's UUID
            // is the gate — exactly as the GUI import does.
            let expectedUUID: String?
            if let value = arguments["uuid"], value != .null {
                guard let uuid = value.stringValue else {
                    throw ScriptingError.invalidArgument("uuid must be a string or null")
                }
                expectedUUID = uuid
            } else {
                expectedUUID = binary.metadata.uuid
            }
            let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)

            // Validate + recover first so the importer's TYPED errors surface as ScriptingError
            // (the store's GUI path swallows them into an alert channel). On success we have the
            // exact recovered set to report; the store call below performs the undoable injection.
            let result: DSYMImportResult
            do {
                result = try DSYMImportService().importDebugSymbols(at: url, expectedUUID: expectedUUID)
            } catch let error as DSYMImportError {
                throw ScriptingError.invalidArgument(error.errorDescription ?? "debug-symbols import failed")
            } catch {
                throw ScriptingError.invalidArgument("could not read debug symbols at \(url.lastPathComponent): \(error.localizedDescription)")
            }
            // HS-9: an overriding `uuid` vouches for the dSYM, never for the image.
            do {
                try result.requireMatchingImage(uuid: binary.metadata.uuid)
            } catch let error as DSYMImportError {
                throw ScriptingError.invalidArgument(error.errorDescription ?? "debug-symbols UUID mismatch")
            }

            // Inject the ALREADY-PARSED result through the same undoable store seam the GUI uses
            // (applies addressability + demangling, registers one Undo group) — NO second parse,
            // so there is no TOCTOU window and the reported counts match what was actually applied.
            store.debugSymbolsResultMessage = nil
            store.debugSymbolsImportError = nil
            let injectedCount = store.injectDebugSymbols(result)
            if let storeError = store.debugSymbolsImportError {
                throw ScriptingError.invalidArgument(storeError)
            }

            return .object([
                "ok": .bool(true),
                "matchedUUID": .string(result.matchedUUID),
                "recoveredFromDWARF": .int(Int64(result.functions.count)),
                "injectedCount": .int(Int64(injectedCount)),
                "dwarf": .string(result.dwarfURL.lastPathComponent),
                "note": .string(store.debugSymbolsResultMessage ?? ""),
            ])
        }

        // --- Workspace documents (HOP-6; WorkspaceScriptingAPI+WorkspaceDocument.swift) ---
        for command in workspaceDocumentCommands {
            commands.append(Command(info: command.info, run: command.run))
        }

        for command in regenerationCommands {
            commands.append(Command(info: command.info, run: command.run))
        }
        for command in regenerationComparisonCommands {
            commands.append(Command(info: command.info, run: command.run))
        }
        for command in calleeClaimCommands { commands.append(Command(info: command.info, run: command.run)) }
        for command in verifiedCommitCommands { commands.append(Command(info: command.info, run: command.run)) }
        for command in verifiedCheckpointIsolatedCommands { commands.append(Command(info: command.info, run: command.run)) }
        return Dictionary(uniqueKeysWithValues: commands.map { ($0.info.name, $0) })
    }()
}
