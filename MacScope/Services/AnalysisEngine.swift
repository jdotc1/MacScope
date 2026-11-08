import Foundation

/// A cooperative cancellation signal threaded through the (synchronous) analysis pipeline so a
/// superseded or user-cancelled re-analysis stops burning CPU at the next pass boundary instead of
/// running a large/hostile binary to completion and then discarding the result. `openBinary` folds
/// Swift task cancellation into it, so the store's existing `reanalysisTask.cancel()` (epoch bump on
/// each new edit) now actually HALTS the in-flight analysis rather than merely ignoring its output.
///
/// Checkpoints sit at pass boundaries (each is O(1) — a closure call + branch), so cancellation is
/// observed between the big passes without perturbing any single pass. The default `.never` makes
/// every existing call site — and the golden/reference oracle, which calls `analyze` directly —
/// byte-identical.
struct AnalysisCancellationToken: Sendable {
    private let _isCancelled: @Sendable () -> Bool
    /// HOP-3: called at every phase checkpoint with the phase about to run.
    private let progress: (@Sendable (AnalysisProgress) -> Void)?
    /// HOP-3: time and memory limits, measured from the token's creation.
    let budget: AnalysisBudget
    private let startedAt: ContinuousClock.Instant
    private let footprint: @Sendable () -> UInt64?

    /// Never cancels. The default for every parameter, so cancellation is strictly opt-in.
    static let never = AnalysisCancellationToken { false }

    init(_ isCancelled: @escaping @Sendable () -> Bool) {
        self.init(storage: isCancelled, budget: .unlimited, progress: nil,
                  footprint: { AnalysisBudget.currentPhysicalFootprint() })
    }

    /// HOP-3: a token that also enforces `budget` and reports `progress` at each phase.
    static func budgeted(
        isCancelled: @escaping @Sendable () -> Bool = { false },
        budget: AnalysisBudget = .unlimited,
        progress: (@Sendable (AnalysisProgress) -> Void)? = nil,
        footprint: @escaping @Sendable () -> UInt64? = { AnalysisBudget.currentPhysicalFootprint() }
    ) -> AnalysisCancellationToken {
        AnalysisCancellationToken(storage: isCancelled, budget: budget, progress: progress, footprint: footprint)
    }

    private init(
        storage isCancelled: @escaping @Sendable () -> Bool,
        budget: AnalysisBudget,
        progress: (@Sendable (AnalysisProgress) -> Void)?,
        footprint: @escaping @Sendable () -> UInt64?
    ) {
        self._isCancelled = isCancelled
        self.budget = budget
        self.progress = progress
        self.startedAt = ContinuousClock.now
        self.footprint = footprint
    }

    var isCancelled: Bool { _isCancelled() }

    /// This token with `extra` folded into its cancellation; the budget, progress and footprint
    /// are kept (the clock restarts). `openBinary` folds Swift task cancellation in this way, so a
    /// caller's budget and progress reach the pipeline instead of being dropped.
    func addingCancellation(_ extra: @escaping @Sendable () -> Bool) -> AnalysisCancellationToken {
        let isCancelled = _isCancelled
        return AnalysisCancellationToken(storage: { isCancelled() || extra() }, budget: budget,
                                         progress: progress, footprint: footprint)
    }

    /// Passes a progress report on to the token's progress handler. The out-of-process provider
    /// relays the worker's reports this way.
    func report(_ progress: AnalysisProgress) {
        self.progress?(progress)
    }

    /// Throws `AnalysisCancelled` when cancellation has been requested. Called at pass boundaries.
    func check() throws {
        if _isCancelled() { throw AnalysisCancelled() }
    }

    /// A named phase boundary: cancellation first, then the budget, then a progress report.
    /// Over budget throws `AnalysisBudgetExceeded` naming the phase it stopped before; the
    /// pipeline never returns a silently truncated snapshot.
    func check(_ phase: AnalysisPhase) throws {
        try check()
        let elapsed = ContinuousClock.now - startedAt
        if let limit = budget.wallClockLimit, elapsed > limit {
            throw AnalysisBudgetExceeded(reason: .wallClock(limit: limit, elapsed: elapsed), stoppedBefore: phase)
        }
        if let limit = budget.physicalFootprintLimitBytes, let used = footprint(), used > limit {
            throw AnalysisBudgetExceeded(reason: .memory(limitBytes: limit, footprintBytes: used), stoppedBefore: phase)
        }
        progress?(AnalysisProgress(phase: phase, elapsed: elapsed))
    }
}

/// HOP-3: the analysis phases, in pipeline order, reported at each checkpoint.
enum AnalysisPhase: String, CaseIterable, Sendable, Equatable {
    case load, decode, functionDiscovery, listing, jumpTables, controlFlow, dataReferences
    case switchHints, diagnostics, rehydrate

    /// 1-based position for a progress bar; `rehydrate` is its own single-phase pipeline.
    var ordinal: Int { (Self.allCases.firstIndex(of: self) ?? 0) + 1 }
    static let analysisPhaseCount = 9
}

struct AnalysisProgress: Sendable, Equatable {
    let phase: AnalysisPhase
    let elapsed: Duration
}

/// HOP-3: a resource budget for one analysis. `nil` limits are unlimited.
struct AnalysisBudget: Sendable, Equatable {
    var wallClockLimit: Duration?
    var physicalFootprintLimitBytes: UInt64?

    static let unlimited = AnalysisBudget(wallClockLimit: nil, physicalFootprintLimitBytes: nil)

    /// This process's physical footprint (what Activity Monitor calls Memory), or nil.
    static func currentPhysicalFootprint() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return info.phys_footprint
    }
}

/// HOP-3: a typed, partial-with-reason outcome. The analysis stopped before `stoppedBefore`;
/// every earlier phase completed. Callers surface the reason instead of a truncated result.
struct AnalysisBudgetExceeded: Error, Equatable, LocalizedError {
    enum Reason: Equatable, Sendable {
        case wallClock(limit: Duration, elapsed: Duration)
        case memory(limitBytes: UInt64, footprintBytes: UInt64)
    }

    let reason: Reason
    let stoppedBefore: AnalysisPhase

    var completedPhases: [AnalysisPhase] {
        Array(AnalysisPhase.allCases.prefix(while: { $0 != stoppedBefore }))
    }

    var errorDescription: String? {
        switch reason {
        case let .wallClock(limit, elapsed):
            return "Analysis stopped before \(stoppedBefore.rawValue): time budget \(limit) exceeded (\(elapsed))."
        case let .memory(limitBytes, footprintBytes):
            return "Analysis stopped before \(stoppedBefore.rawValue): memory budget \(limitBytes) bytes exceeded (\(footprintBytes))."
        }
    }
}

/// Thrown by the analysis pipeline when a cooperative cancellation checkpoint observes a cancel.
/// The interactive re-analysis path already discards a superseded result, so this error is
/// swallowed there (`try?`); it exists so a checkpoint can unwind the pipeline promptly.
struct AnalysisCancelled: Error {}

enum AnalysisEngineError: LocalizedError, Equatable {
    case unreadableInput
    case noExecutableCode
    /// The loader declared a selected-slice extent that does not fit inside the container
    /// bytes (`sliceOffset + sliceSize > containerSize`, or an offset past the end). Refused
    /// rather than silently clamped, so a malformed fat entry can never cause the pipeline to
    /// persist a truncated or over-reaching payload.
    case invalidSelectedSliceRange(offset: UInt64, size: UInt64?, containerSize: Int)

    var errorDescription: String? {
        switch self {
        case .unreadableInput:
            "The selected file could not be read by the current importer."
        case .noExecutableCode:
            "The imported Mach-O file does not expose an executable text section."
        case let .invalidSelectedSliceRange(offset, size, containerSize):
            "The selected slice range (offset \(offset), size \(size.map(String.init) ?? "to-end")) "
                + "does not fit in the \(containerSize)-byte container."
        }
    }
}

/// `Sendable` so the (pure, stateless) engine can be captured into a background task and run off
/// the main actor — `loader`/`Disassembler` are `Sendable` protocols and `decoderProvider` is a
/// `@Sendable` closure, so the whole value crosses actor boundaries safely.
struct AnalysisEngine: Sendable {
    var attribution: AnalysisAttribution? = nil
    /// Stage A observer held by the enabled attribution; nil whenever the opt-in is off.
    private var work: StartupWorkCounters? { attribution?.work }
    /// Test seam: invoked at each cancellation checkpoint; nil in production.
    var checkpointForTesting: (@Sendable (AnalysisPhase) -> Void)? = nil

    private func checkAnalysisCheckpoint(_ phase: AnalysisPhase,
                                         cancellation: AnalysisCancellationToken) throws {
        checkpointForTesting?(phase)
        try cancellation.check(phase)
    }

    /// HOP-1: discovery re-runs after no-return propagation at most this many times.
    static let maximumNoReturnDiscoveryRounds = 3
    // The binary is loaded through this format-agnostic seam (Mach-O today; ELF/PE
    // plug in by conforming to `BinaryLoader`), so the pipeline below consumes only
    // the neutral `LoadedBinary` and never a format-specific type.
    private let loader: any BinaryLoader
    /// Worker-only compiler metadata enrichment over the captured, validated image.
    private let binaryEnrichment: (@Sendable (LoadedBinary) -> LoadedBinary)?
    // The decoder is chosen per-binary by CPU type (arm64 vs x86_64) through this
    // provider, so the pipeline consumes whichever `Disassembler` fits the loaded
    // binary without any other code knowing the architecture.
    private let decoderProvider: @Sendable (LoadedBinary) -> any Disassembler
    // Immutable, validated library-function recognizer. The generated standard
    // corpus is empty during Phase A, so existing analysis short-circuits before
    // candidate construction and remains byte-identical.
    private let functionSignatureMatcher: FunctionSignatureMatcher
    // Independent parser engines (RX-03). Only the analysis worker injects one; it re-parses the
    // exact selected-slice bytes and surfaces disagreements as diagnostics, never as authority.
    let parserCrossCheck: (any ParserCrossChecking)?
    // Engine verdicts by selected-slice digest (D4). The worker passes its process-wide cache so
    // every connection's engine shares it; other callers get a private one.
    let parserCrossCheckCache: ParserCrossCheckVerdictCache
    // Largest selected slice handed to the engines; larger slices get a skip diagnostic.
    let parserCrossCheckByteLimit: Int
    // HOP-5: `noReturn` names (NoReturnCatalog.canonicalName keys) from the shipped SDK signature
    // pack, consulted after NoReturnCatalog. Tests may substitute a set.
    var sdkPackNoReturnNames: Set<String> = CallSignaturePack.bundledNoReturnCanonicalNames

    init(
        loader: any BinaryLoader = BinaryLoaderRouter(),
        decoderProvider: @escaping @Sendable (LoadedBinary) -> any Disassembler = AnalysisEngine.architectureDecoder,
        functionSignatureMatcher: FunctionSignatureMatcher = .standard,
        parserCrossCheck: (any ParserCrossChecking)? = nil,
        parserCrossCheckCache: ParserCrossCheckVerdictCache = ParserCrossCheckVerdictCache(),
        parserCrossCheckByteLimit: Int = AnalysisEngine.maximumParserCrossCheckBytes,
        binaryEnrichment: (@Sendable (LoadedBinary) -> LoadedBinary)? = nil
    ) {
        self.loader = loader
        self.decoderProvider = decoderProvider
        self.functionSignatureMatcher = functionSignatureMatcher
        self.parserCrossCheck = parserCrossCheck
        self.parserCrossCheckCache = parserCrossCheckCache
        self.parserCrossCheckByteLimit = parserCrossCheckByteLimit
        self.binaryEnrichment = binaryEnrichment
    }

    /// Convenience/test initializer that forces a specific decoder regardless of the
    /// binary's architecture.
    init(
        loader: any BinaryLoader = BinaryLoaderRouter(),
        decoder: any Disassembler,
        functionSignatureMatcher: FunctionSignatureMatcher = .standard
    ) {
        self.loader = loader
        self.decoderProvider = { _ in decoder }
        self.functionSignatureMatcher = functionSignatureMatcher
        self.parserCrossCheck = nil
        self.parserCrossCheckCache = ParserCrossCheckVerdictCache()
        self.parserCrossCheckByteLimit = AnalysisEngine.maximumParserCrossCheckBytes
        self.binaryEnrichment = nil
    }

    /// Selects the decoder for a loaded binary by CPU type. x86_64 routes to the x86
    /// decoder; arm64 — including arm64e, which shares the arm64 cpuType and differs
    /// only by subtype — routes to the arm64 decoder. Every OTHER cpuType (32-bit ARM,
    /// i386, PowerPC, or a corrupt/unknown value — all out of scope per PARITY_CONTRACT.md
    /// §4) routes to `UnsupportedArchitectureDecoder`, which surfaces the bytes as data
    /// with a diagnostic rather than silently mis-decoding them as arm64.
    static func architectureDecoder(for binary: LoadedBinary) -> any Disassembler {
        switch binary.cpuType {
        case MachOConstants.cpuTypeX86_64: return X86_64Decoder()
        case MachOConstants.cpuTypeARM64: return ARM64Decoder()
        default: return UnsupportedArchitectureDecoder(cpuType: binary.cpuType)
        }
    }

    /// Schema v1 is deliberately narrower than the decoder: it recognizes only
    /// Mach-O arm64 `CPU_SUBTYPE_ARM64_ALL`. arm64e and format-neutral arm64
    /// inputs abstain because the checked-in corpus has no oracle for them.
    static func functionSignatureArchitecture(
        for binary: LoadedBinary
    ) -> FunctionSignatureArchitecture? {
        guard binary.cpuType == MachOConstants.cpuTypeARM64,
              let rawSubtype = binary.cpuSubtype else {
            return nil
        }
        let normalizedSubtype = UInt32(bitPattern: rawSubtype) & 0x00FF_FFFF
        guard normalizedSubtype == 0 else { return nil }
        return .arm64
    }

    struct FunctionSignatureProjection {
        var functions: [FunctionSummary]
        var symbols: [SymbolSummary]
    }

    /// Applies only unique matches to exact generated fallbacks. Keeping this
    /// projection pure makes the precedence and identity-preservation contract
    /// independently testable without re-running UUID-producing discovery.
    static func projectFunctionSignatureMatches(
        functions: [FunctionSummary],
        candidatesByStartAddress: [UInt64: FunctionSignatureCandidate],
        matcher: FunctionSignatureMatcher,
        authoritativeAddresses: Set<UInt64>
    ) -> FunctionSignatureProjection {
        var projectedFunctions = functions
        var projectedSymbols: [SymbolSummary] = []

        for index in projectedFunctions.indices {
            let function = projectedFunctions[index]
            let fallbackName = "sub_\(function.startAddress.hexAddress)"
            guard function.name == fallbackName,
                  !authoritativeAddresses.contains(function.startAddress),
                  let candidate = candidatesByStartAddress[function.startAddress],
                  case let .unique(identity) = matcher.match(candidate) else {
                continue
            }
            projectedFunctions[index].name = identity.name
            projectedSymbols.append(
                SymbolSummary(
                    id: UUID(),
                    name: identity.name,
                    address: function.startAddress,
                    kind: "library-signature",
                    libraryName: identity.libraryName
                )
            )
        }

        projectedSymbols.sort {
            if $0.address != $1.address {
                return ($0.address ?? 0) < ($1.address ?? 0)
            }
            if $0.name != $1.name { return $0.name < $1.name }
            return ($0.libraryName ?? "") < ($1.libraryName ?? "")
        }
        return FunctionSignatureProjection(
            functions: projectedFunctions,
            symbols: projectedSymbols
        )
    }

    /// Builds the exact effective-byte candidate for one already-discovered
    /// function. Any gap, overlap, zero-width row, overflow, or truncation makes
    /// the range ineligible; a partial byte sequence is never matched.
    static func functionSignatureCandidate(
        for function: FunctionSummary,
        architecture: FunctionSignatureArchitecture,
        instructions: [DecodedInstruction],
        referenceNamesByAddress: [UInt64: String]
    ) -> FunctionSignatureCandidate? {
        candidate(
            for: function,
            architecture: architecture,
            sortedRows: instructions.sorted { $0.address < $1.address },
            referenceNamesByAddress: referenceNamesByAddress
        )
    }

    /// Creates every candidate from one address-sorted instruction stream. The
    /// binary searches avoid rescanning/re-sorting the complete stream for each
    /// function while retaining a pure per-range adapter for focused tests.
    private static func functionSignatureCandidates(
        for functions: [FunctionSummary],
        architecture: FunctionSignatureArchitecture,
        instructions: [DecodedInstruction],
        referenceNamesByAddress: [UInt64: String]
    ) -> [UInt64: FunctionSignatureCandidate] {
        let sortedRows = instructions.sorted { $0.address < $1.address }
        var candidates: [UInt64: FunctionSignatureCandidate] = [:]
        for function in functions {
            let lower = lowerBound(
                of: function.startAddress,
                in: sortedRows
            )
            let upper = lowerBound(
                of: function.endAddress,
                in: sortedRows
            )
            if let value = candidate(
                for: function,
                architecture: architecture,
                sortedRows: sortedRows[lower..<upper],
                referenceNamesByAddress: referenceNamesByAddress
            ) {
                candidates[function.startAddress] = value
            }
        }
        return candidates
    }

    private static func lowerBound(
        of address: UInt64,
        in instructions: [DecodedInstruction]
    ) -> Int {
        var low = 0
        var high = instructions.count
        while low < high {
            let middle = low + (high - low) / 2
            if instructions[middle].address < address {
                low = middle + 1
            } else {
                high = middle
            }
        }
        return low
    }

    private static func candidate<Rows: Collection>(
        for function: FunctionSummary,
        architecture: FunctionSignatureArchitecture,
        sortedRows: Rows,
        referenceNamesByAddress: [UInt64: String]
    ) -> FunctionSignatureCandidate? where Rows.Element == DecodedInstruction {
        guard function.endAddress > function.startAddress,
              function.startAddress.isMultiple(of: 4),
              function.endAddress.isMultiple(of: 4) else {
            return nil
        }
        let byteCount = function.endAddress - function.startAddress
        guard byteCount <= 1_048_576,
              byteCount.isMultiple(of: 4),
              !sortedRows.isEmpty,
              sortedRows.count == Int(byteCount / 4) else {
            return nil
        }

        var cursor = function.startAddress
        var bytes: [UInt8] = []
        bytes.reserveCapacity(Int(byteCount))
        var references: [UInt32: String] = [:]
        for row in sortedRows {
            guard row.address == cursor,
                  row.address.isMultiple(of: 4),
                  row.bytes.count == 4 else {
                return nil
            }
            bytes.append(contentsOf: row.bytes)
            if (row.flow == .call || row.flow == .jump),
               let target = row.branchTarget,
               let name = referenceNamesByAddress[target],
               let offset = UInt32(exactly: row.address - function.startAddress) {
                references[offset] = name
            }
            cursor += 4
        }
        guard cursor == function.endAddress else { return nil }
        return FunctionSignatureCandidate(
            architecture: architecture,
            bytes: bytes,
            importedReferences: references
        )
    }

    /// Resolves reference evidence only when every authoritative source at a
    /// target agrees on one nonempty name. Conflicting loader symbols or a
    /// symbol/stub disagreement omit the offset and therefore fail any record
    /// that requires it.
    private static func uniqueReferenceNames(
        symbols: [SymbolSummary],
        indirectSymbols: [IndirectSymbolSummary]
    ) -> [UInt64: String] {
        var namesByAddress: [UInt64: Set<String>] = [:]
        for symbol in symbols {
            guard let address = symbol.address, !symbol.name.isEmpty else { continue }
            namesByAddress[address, default: []].insert(symbol.name)
        }
        for entry in indirectSymbols {
            let sectionName = entry.sourceSection
                .split(separator: ",")
                .last
                .map(String.init) ?? entry.sourceSection
            guard StubCallSymbolicator.linkageSections.contains(sectionName),
                  !entry.isLocal,
                  !entry.isAbsolute,
                  let name = entry.symbolName,
                  !name.isEmpty else {
                continue
            }
            namesByAddress[entry.address, default: []].insert(name)
        }
        return namesByAddress.compactMapValues { names in
            names.count == 1 ? names.first : nil
        }
    }

    /// Loads + analyzes a binary OFF the main actor. This is `nonisolated async`, so awaiting it
    /// from a `@MainActor` caller (the store) runs the whole heavy pipeline on the cooperative
    /// thread pool instead of freezing the UI; the `Sendable` `WorkspaceSnapshot` result then hops
    /// back to the caller's actor. (`AnalysisEngine` + `WorkspaceSnapshot` are `Sendable`, so the
    /// engine value and the result cross the boundary safely.)
    ///
    /// `overrides` lets the same off-main entry serve the store's background RE-analysis after a
    /// mark-as-code/data/procedure edit: the synchronous core honors the override map, and because
    /// this wrapper is `async`, awaiting it keeps the re-flow off the main thread too (defaults to
    /// empty for the initial open, which has no authoring layer yet).
    func openBinary(
        url: URL,
        requestedSliceIndex: Int? = nil,
        overrides: [UInt64: AddressOverride] = [:],
        cancellation: AnalysisCancellationToken = .never
    ) async throws -> WorkspaceSnapshot {
        try await openBinary(
            url: url,
            selection: .machOSlice(requestedSliceIndex),
            overrides: overrides,
            cancellation: cancellation
        )
    }

    func openBinary(
        url: URL,
        selection: BinaryLoadSelection,
        overrides: [UInt64: AddressOverride] = [:],
        cancellation: AnalysisCancellationToken = .never
    ) async throws -> WorkspaceSnapshot {
        // Fold Swift task cancellation into the explicit token: because this runs inside the
        // store's `reanalysisTask`, cancelling that task (which the store already does on every
        // new edit) now flips `Task.isCancelled` and the synchronous core unwinds at its next
        // checkpoint. The two signals compose so an explicit caller token still works too.
        // Keep the caller's HOP-3 budget and progress: rebuilding a plain token here dropped them,
        // so neither ever reached the pipeline in production.
        let combined = cancellation.addingCancellation { Task.isCancelled }
        return try analyze(
            url: url,
            selection: selection,
            overrides: overrides,
            cancellation: combined
        )
    }

    /// The synchronous analysis core (no awaits) — `nonisolated`, so it runs wherever it is
    /// called: off-main under `openBinary`'s task, and synchronously on the main thread for the
    /// headless MCP launcher (no SwiftUI run loop to drive an async task) and the store's
    /// re-analysis path. It touches no actor-isolated state.
    ///
    /// `requestedSliceIndex` picks an explicit fat/universal Mach-O slice (the user's
    /// dialog choice). When set, this call routes through a slice-specific loader rather
    /// than the engine's default; `nil` uses the default loader and selection rule.
    func analyze(
        url: URL,
        requestedSliceIndex: Int? = nil,
        overrides: [UInt64: AddressOverride] = [:],
        cancellation: AnalysisCancellationToken = .never
    ) throws -> WorkspaceSnapshot {
        try analyze(
            url: url,
            selection: .machOSlice(requestedSliceIndex),
            overrides: overrides,
            cancellation: cancellation
        )
    }

    func analyze(
        url: URL,
        selection: BinaryLoadSelection,
        overrides: [UInt64: AddressOverride] = [:],
        cancellation: AnalysisCancellationToken = .never
    ) throws -> WorkspaceSnapshot {
        let analysisInterval = MacScopePerformance.begin("Analysis.total")
        defer { MacScopePerformance.end("Analysis.total", analysisInterval) }
        let totalSpan = attribution?.open(.analysisTotal)
        var currentSpan = attribution?.open(.load)
        var attributionOutcome: AnalysisAttribution.Outcome = .failed
        work?.beginAnalysis()
        defer {
            work?.finishAnalysis(attributionOutcome)
            if let attribution {
                attribution.close(currentSpan, outcome: attributionOutcome)
                attribution.close(totalSpan, outcome: attributionOutcome)
            }
        }
        do {
        try checkAnalysisCheckpoint(.load, cancellation: cancellation)
        let usesAutomaticSelection = selection == .automatic
        let loader: any BinaryLoader = usesAutomaticSelection
            ? self.loader
            : BinaryLoaderRouter(selection: selection)
        let captured = try MacScopePerformance.measure("Analysis.load") {
            try loader.load(at: url, cancellation: cancellation)
        }
        try validateSelectedSliceRange(of: captured)
        try checkAnalysisCheckpoint(.load, cancellation: cancellation)
        let loaded = binaryEnrichment?(captured) ?? captured
        try checkAnalysisCheckpoint(.load, cancellation: cancellation)

        let containerWitness: MachOContainerAdmissionWitness? = {
            guard loaded.artifactIntegrityState == .verified,
                  let identity = loaded.artifactIdentity else { return nil }
            return MachOContainerAdmissionWitness(
                containerBytes: loaded.bytes,
                sliceOffset: loaded.sliceOffset,
                sliceSize: loaded.sliceSize,
                selectedSliceIdentity: identity,
                sourceFileStamp: loaded.nativeExecutionFileStamp
            )
        }()
        let image = BinaryImage(
            id: UUID(),
            name: loaded.name,
            path: loaded.path,
            kind: loaded.isBundle ? "app bundle" : loaded.fileTypeName,
            architecture: loaded.architectureDisplayName,
            metadata: loaded.metadata,
            selectedSliceIndex: loaded.machOSelectedSliceFact?.universalSliceIndex,
            machOSelectedSliceFact: loaded.machOSelectedSliceFact,
            elfArchiveMemberIdentity: loaded.loadSelection.elfArchiveMember,
            artifactIdentity: loaded.artifactIdentity,
            preferredSegmentLayout: loaded.preferredSegmentLayout,
            artifactIntegrityState: loaded.artifactIntegrityState,
            containerAdmissionWitness: containerWitness,
            resolvedExecutablePath: loaded.resolvedExecutablePath
        )

        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.decode)
        }
        try checkAnalysisCheckpoint(.decode, cancellation: cancellation)
        let codeSection = loaded.executableTextSection
        let decoder = decoderProvider(loaded)
        // Decode one effective stream, retaining original bytes outside every edit.
        // The original attachment remains raw artifact authority; this derived overlay
        // is also used for table reads and never grants native effective-byte authority.
        let byteMappings = makeByteMappings(loaded: loaded)
        let patchOverlay = try BytePatchOverlay(
            patches: overrides.compactMapValues { $0.patch }, mappings: byteMappings
        )
        let decodedInstructions = MacScopePerformance.measure("Analysis.decode") {
            decodeInstructions(
                from: loaded, decoder: decoder, patchOverlay: patchOverlay, byteMappings: byteMappings
            )
        }
        work?.close(.decodeAdmission)
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.dataMembership)
        }
        // Addresses the user marked as DATA are excluded from EVERY analysis pass
        // (function discovery, basic blocks, CFG, call/data xrefs) — so the analyst's
        // mark actually re-drives the analysis. The FULL decoded set is still kept for
        // the listing, which renders those rows as `.long`/`.byte` data directives.
        // A plain mark-as-data OR a data SHAPE (Make Array / Make Alignment / Make
        // String) OR a Mark-as-Undefined excludes the address from code analysis — all
        // three are equally "not code" for discovery/blocks/CFG/xref purposes (the listing
        // still renders each distinctly: data directive vs `.byte` undefined).
        let authoredDataAddresses = Set(overrides.compactMap {
            ($0.value.isData || $0.value.isUndefined || !($0.value.dataShape?.isEmpty ?? true)) ? $0.key : nil
        })
        let loaderDataAddresses: Set<UInt64>
        if loaded.codeDataRanges.count > 8 {
            let index = CodeDataRangeIndex(ranges: loaded.codeDataRanges)
            loaderDataAddresses = Set(decodedInstructions.compactMap { decoded in
                index.contains(address: decoded.address) ? decoded.address : nil
            })
            attribution?.add(.validRanges, index.validRangeCount)
        } else {
            loaderDataAddresses = Set(decodedInstructions.compactMap { decoded -> UInt64? in
                loaded.codeDataRanges.contains { range in
                    guard range.size > 0 else { return false }
                    let (end, overflow) = range.address.addingReportingOverflow(range.size)
                    guard !overflow else { return false }
                    return decoded.address >= range.address && decoded.address < end
                } ? decoded.address : nil
            })
            if let attribution {
                let valid = loaded.codeDataRanges.reduce(0) { count, range in
                    count + ((range.size > 0 && !range.address.addingReportingOverflow(range.size).overflow) ? 1 : 0)
                }
                attribution.add(.validRanges, valid)
            }
        }
        if let attribution {
            attribution.add(.decodedInstructions, decodedInstructions.count)
            attribution.add(.loaderRanges, loaded.codeDataRanges.count)
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.codeFilter)
        }
        let dataAddresses = authoredDataAddresses.union(loaderDataAddresses)
        // Addresses the user FORCED to be function starts (Mark as Procedure) — the manual
        // lever that splits a function the heuristic discovery merged.
        let procedureAddresses = Set(overrides.compactMap { $0.value.markAsProcedure ? $0.key : nil })
        let codeInstructions = dataAddresses.isEmpty
            ? decodedInstructions
            : decodedInstructions.filter { !dataAddresses.contains($0.address) }
        work?.add(.codeInstructions, codeInstructions.count)
        work?.close(.codeFilter)
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.discoverySetup)
        }
        try checkAnalysisCheckpoint(.functionDiscovery, cancellation: cancellation)
        // Symbol/import/export/string tables are already projected into neutral
        // summaries by the loader.
        let symbolSummaries = loaded.symbols
        let importSummaries = loaded.imports
        let indirectSymbolSummaries = loaded.indirectSymbols
        // Symbolicate import stubs / GOT slots: each linkage-section slot's VA gets a synthetic
        // symbol named after the import it forwards to, so the listing's label lookup resolves a
        // `bl <stub>` / `adrp;ldr [__got]` target to `_printf` / `_objc_msgSend` instead of a bare
        // address. Sorted by address for deterministic output; a real symbol at the same address
        // always wins (only the unnamed slots are filled).
        let stubSymbolicator = StubCallSymbolicator(
            indirectSymbols: indirectSymbolSummaries,
            objcStubNames: Self.objcStubSelectorNames(in: loaded)
        )
        // HOP-1: calls to known no-return targets end their block and function. Discovery runs
        // with the catalog targets, then propagation ("every exit halts") adds functions and
        // discovery re-runs so prologues hidden behind the new halts are recovered. Bounded.
        let catalogNoReturnTargets = NoReturnAnalysis.catalogTargets(
            symbols: symbolSummaries,
            stubNamesByAddress: stubSymbolicator.nameByStubAddress
        )
        // HOP-5: the shipped SDK pack's `noReturn` names add targets the catalog lacks.
        let sdkPackNoReturnTargets = NoReturnAnalysis.sdkPackTargets(
            symbols: symbolSummaries,
            stubNamesByAddress: stubSymbolicator.nameByStubAddress,
            noReturnNames: sdkPackNoReturnNames
        ).subtracting(catalogNoReturnTargets)
        let codeSections = executableCodeSections(in: loaded, mappings: byteMappings)
        work?.add(.codeSectionBuilds)
        work?.close(.admission)
        var preparation: DiscoveryPreparationStore? = DiscoveryPreparationStore(work: work)
        defer {
            if let attribution, let preparation {
                attribution.add(.preparedEntries, preparation.statistics.retainedEntries)
                attribution.add(.cacheAdmissions, preparation.statistics.admissions)
                attribution.add(.cacheRefusals, preparation.statistics.refusals)
            }
        }
        var discoveryOrdinal = 0
        work?.add(.sections, codeSections.count)
        work?.close(.setup)
        if let attribution {
            attribution.add(.sections, codeSections.count)
            attribution.close(currentSpan, outcome: .success)
            currentSpan = nil
        }
        func discoverFunctions(noReturnTargets: Set<UInt64>) -> [FunctionSummary] {
            discoveryOrdinal += 1
            let span = attribution?.open(.discoveryRecover, ordinal: discoveryOrdinal)
            defer { attribution?.close(span, outcome: .success) }
            attribution?.add(.discoveryInvocations, 1)
            if let work {
                work.add(.discoveryInvocations)
                work.begin(.sliceCopiesAvoided)
                work.begin(.sectionCallsAttempted)
                work.begin(.sectionCallsCompleted)
            }
            return codeSections.enumerated().flatMap { sectionOrdinal, interval in
                let end = interval.address + interval.size // admission checked the sum
                attribution?.add(.sliceCopiesAvoided, 1)
                if let work {
                    work.add(.sliceCopiesAvoided)
                    work.add(.sectionCallsAttempted)
                }
                return makeFunctionSummaries(from: loaded, codeSection: interval,
                    decodedInstructions: codeInstructions[Self.addressIndex(interval.address, in: codeInstructions, address: \.address)
                        ..< Self.addressIndex(end, in: codeInstructions, address: \.address)],
                    dataAddresses: dataAddresses, procedureAddresses: procedureAddresses,
                    noReturnTargets: noReturnTargets, preparation: preparation!,
                    sectionOrdinal: sectionOrdinal, discoveryOrdinal: discoveryOrdinal)
            }
        }
        var noReturnTargets = catalogNoReturnTargets.union(sdkPackNoReturnTargets)
        var functions = discoverFunctions(noReturnTargets: noReturnTargets)
        var propagatedNoReturnStarts = Set<UInt64>()
        for _ in 0..<Self.maximumNoReturnDiscoveryRounds {
            let derived: Set<UInt64>
            do {
                let span = attribution?.open(.discoveryPropagate, ordinal: discoveryOrdinal)
                defer { attribution?.close(span, outcome: .success) }
                derived = NoReturnAnalysis.propagate(
                    functions: functions, instructions: codeInstructions, known: noReturnTargets,
                    work: work
                )
            }
            guard !derived.isEmpty else { break }
            propagatedNoReturnStarts.formUnion(derived)
            noReturnTargets.formUnion(derived)
            try checkAnalysisCheckpoint(.functionDiscovery, cancellation: cancellation)
            functions = discoverFunctions(noReturnTargets: noReturnTargets)
        }
        work?.close(.discovery)
        if let attribution, let preparation {
            attribution.add(.preparedEntries, preparation.statistics.retainedEntries)
            attribution.add(.cacheAdmissions, preparation.statistics.admissions)
            attribution.add(.cacheRefusals, preparation.statistics.refusals)
            currentSpan = attribution.open(.discoveryFinish)
        }
        // Only the scalar caches survive rounds; none survives discovery.
        preparation?.release()
        preparation = nil
        functions = functions.map { function in
            var function = function
            if catalogNoReturnTargets.contains(function.startAddress) {
                function.noReturnProvenance = .catalog
            } else if sdkPackNoReturnTargets.contains(function.startAddress) {
                function.noReturnProvenance = .sdkPack
            } else if propagatedNoReturnStarts.contains(function.startAddress) {
                function.noReturnProvenance = .propagated
            }
            return function
        }
        let librarySignatureSymbols: [SymbolSummary]
        if !functionSignatureMatcher.isEmpty,
           let architecture = Self.functionSignatureArchitecture(for: loaded) {
            let referenceNames = Self.uniqueReferenceNames(
                symbols: symbolSummaries,
                indirectSymbols: indirectSymbolSummaries
            )
            let candidates = Self.functionSignatureCandidates(
                for: functions,
                architecture: architecture,
                instructions: codeInstructions,
                referenceNamesByAddress: referenceNames
            )
            let authoritativeAddresses = Set(symbolSummaries.compactMap(\.address))
                .union(loaded.exports.compactMap(\.address))
            let projection = Self.projectFunctionSignatureMatches(
                functions: functions,
                candidatesByStartAddress: candidates,
                matcher: functionSignatureMatcher,
                authoritativeAddresses: authoritativeAddresses
            )
            functions = projection.functions
            librarySignatureSymbols = projection.symbols
        } else {
            librarySignatureSymbols = []
        }
        let namedSymbolAddresses = Set(symbolSummaries.compactMap(\.address))
            .union(librarySignatureSymbols.compactMap(\.address))
            .union(loaded.exports.compactMap(\.address))
        let stubSymbols: [SymbolSummary] = stubSymbolicator.nameByStubAddress
            .filter { !namedSymbolAddresses.contains($0.key) }
            .sorted { $0.key < $1.key }
            .map { SymbolSummary(id: UUID(), name: $0.value, address: $0.key, kind: "stub", libraryName: nil) }
        let objcNaming = Self.projectObjCMethodNames(
            functions: functions, classes: loaded.objcClasses, categories: loaded.objcCategories,
            namedAddresses: namedSymbolAddresses.union(stubSymbols.compactMap(\.address)),
            existingNames: (symbolSummaries + librarySignatureSymbols + stubSymbols).map(\.name)
                + loaded.exports.map(\.name))
        functions = objcNaming.functions
        let exportSummaries = loaded.exports
        var stringLiteralSummaries = loaded.stringLiterals

        // The listing rows are a pure 1:1 projection of the decoded stream — independent per
        // element and the single hottest pass (the per-instruction byteText hex formatting × N).
        // Map it in parallel; the index-ordered result is byte-identical to a sequential map.
        // Cancellation is checked at the pass boundary (before/after) rather than inside the
        // parallel map: a per-element check would race across `concurrentPerform` workers for no
        // real benefit, since this pass is already core-parallel and bounded.
        if let attribution {
            attribution.add(.functions, functions.count)
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.listing)
        }
        try checkAnalysisCheckpoint(.listing, cancellation: cancellation)
        var instructionRows = ConcurrentMap.map(count: decodedInstructions.count) { index in
            let decoded = decodedInstructions[index]
            return InstructionRow(decoded: decoded)
        }
        // Cross-annotate metadata → code: an ObjC method IMP with no symbol of its own gets a
        // comment naming its defining class and selector, so a stripped body still says what it is.
        let objcImplementationComments = Self.objcImplementationComments(
            classes: loaded.objcClasses,
            categories: loaded.objcCategories,
            namedAddresses: namedSymbolAddresses.union(stubSymbols.compactMap(\.address))
        )
        if !objcImplementationComments.isEmpty {
            for index in instructionRows.indices {
                guard let note = objcImplementationComments[instructionRows[index].address] else { continue }
                instructionRows[index].comment = instructionRows[index].comment.map { "\(note) ; \($0)" } ?? note
            }
        }
        // The row-based passes (jump-table recovery, data xrefs) derive from CODE ONLY — a
        // data-marked `br`/`adrp` sequence must not synthesize a phantom jump table or
        // reference. The full `instructionRows` is kept for the listing.
        let codeInstructionRows = dataAddresses.isEmpty
            ? instructionRows
            : instructionRows.filter { !dataAddresses.contains($0.address) }
        // Jump tables are resolved BEFORE the CFG passes so a `br` switch dispatch can seed
        // its case targets as block leaders and emit a successor edge to each of them.
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.jumpTables)
        }
        try checkAnalysisCheckpoint(.jumpTables, cancellation: cancellation)
        let jumpTables = try resolveJumpTables(
            instructionRows: codeInstructionRows,
            loaded: loaded,
            functions: functions,
            patchOverlay: patchOverlay,
            byteMappings: byteMappings, cancellation: cancellation
        )
        work?.close(.jump)

        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.blocks)
        }
        try checkAnalysisCheckpoint(.controlFlow, cancellation: cancellation)
        let basicBlocks = buildBasicBlocks(
            from: codeInstructions,
            functions: functions,
            codeStart: codeSection?.address,
            jumpTables: jumpTables,
            noReturnTargets: noReturnTargets
        )
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.edges)
        }
        let controlFlowEdges = buildControlFlowEdges(
            from: codeInstructions,
            basicBlocks: basicBlocks,
            jumpTables: jumpTables,
            noReturnTargets: noReturnTargets
        )

        let objcSelectors = loaded.objcSelectors

        // Direct calls (arm64 `bl`, x86 `call`) plus recovered DATA references
        // (string/selref/global) from the adrp-pairing pass. Both are materialized
        // into `xrefs` so they persist through save/reload like any other xref.
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.callXrefs)
        }
        let callXRefs: [XRef] = codeInstructions.compactMap { decoded in
            guard decoded.flow == .call, let target = decoded.branchTarget else { return nil }
            return XRef(id: UUID(), from: decoded.address, to: target, kind: XRefKind.call)
        }
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.dataXrefs)
        }
        try checkAnalysisCheckpoint(.dataReferences, cancellation: cancellation)
        let dataXRefs = DataCrossReferenceResolver().resolveParallel(
            instructions: codeInstructionRows,
            stringAddresses: Set(stringLiteralSummaries.map(\.address)),
            selectorSlots: Set(objcSelectors.keys),
            classSlots: Set(loaded.objcClassReferences.keys),
            dataRanges: loaded.sections
                .filter { (!$0.isExecutable || $0.containsCStringLiterals == true) && $0.size > 0 }
                .compactMap { section in
                    let (end, overflow) = section.address.addingReportingOverflow(section.size)
                    guard !overflow else { return nil }
                    return DataCrossReferenceResolver.DataRange(lowerBound: section.address, upperBound: end)
                } + loaded.codeDataRanges.compactMap { range in
                    let (end, overflow) = range.address.addingReportingOverflow(range.size)
                    guard range.size > 0, !overflow else { return nil }
                    return DataCrossReferenceResolver.DataRange(lowerBound: range.address, upperBound: end)
                }
        ).map { XRef(id: UUID(), from: $0.from, to: $0.to, kind: $0.kind) }

        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.stringRecovery)
        }
        let sectionSummaries = loaded.sections.map {
            SectionSummary(id: UUID(), name: $0.name, address: $0.address, size: $0.size,
                fileOffset: $0.fileOffset, isExecutable: $0.isExecutable, isZeroFill: $0.isZeroFill,
                fileSize: $0.fileSize, coffCoordinate: $0.coffCoordinate,
                containsCStringLiterals: $0.containsCStringLiterals)
        }
        stringLiteralSummaries = try ReferencedStringRecovery.recover(
            retained: stringLiteralSummaries, coverage: loaded.stringLiteralCoverage,
            references: dataXRefs, sections: sectionSummaries, bytes: loaded.bytes,
            sliceOffset: loaded.sliceOffset, sliceSize: loaded.sliceSize, overlay: patchOverlay,
            work: work,
            checkpoint: { try checkAnalysisCheckpoint(.dataReferences, cancellation: cancellation) })
        work?.close(.string)
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.snapshot)
        }
        var snapshot = WorkspaceSnapshot(
            binaries: [image],
            functions: functions,
            // HOP-4: symbol ids derive from (image slot, address, name, kind), not fresh UUIDs.
            symbols: AnalysisStableIdentity.assigningSymbolIDs(
                symbolSummaries + librarySignatureSymbols + stubSymbols + objcNaming.symbols, slot: .primary
            ),
            imports: importSummaries,
            indirectSymbols: indirectSymbolSummaries,
            exports: exportSummaries,
            stringLiterals: stringLiteralSummaries,
            stringLiteralCoverage: loaded.stringLiteralCoverage,
            basicBlocks: basicBlocks,
            instructions: instructionRows,
            xrefs: callXRefs + dataXRefs,
            controlFlowEdges: controlFlowEdges,
            hexBytes: selectedSliceBytes(from: loaded),
            jumpTables: jumpTables,
            objcSelectors: objcSelectors,
            objcClassReferences: loaded.objcClassReferences,
            constantStrings: ImageConstantStringProvider.build(
                stringLiterals: stringLiteralSummaries, cfStrings: loaded.constantCFStrings
            ),
            cfStringBackings: loaded.cfStringBackings,
            objcClasses: loaded.objcClasses,
            objcCategories: loaded.objcCategories,
            objcProtocols: loaded.objcProtocols,
            swiftTypes: loaded.swiftTypes,
            swiftConformances: loaded.swiftConformances,
            sections: sectionSummaries,
            codeDataRanges: loaded.codeDataRanges.map {
                CodeDataRangeSummary(id: UUID(), address: $0.address, size: $0.size, kind: $0.kind)
            },
            relocations: loaded.relocations,
            identityEffectiveByteRanges: loaded.identityEffectiveByteRanges,
            imageBytes: sliceBytes(from: loaded),
            // Carry the honored overrides into the result so a re-analyzed snapshot keeps
            // the authoring layer (the initial open passes `[:]`, unchanged from before).
            // The engine is IMAGE-LOCAL — it analyzes exactly one image and never sees a
            // sibling — so its override world stays bare-UInt64 and is qualified here, at
            // the workspace boundary, as the primary slot. The store re-stamps the real
            // slot when splicing a re-analysis into a multi-image workspace.
            addressOverrides: Dictionary(uniqueKeysWithValues: overrides.map {
                (ImageAddress(slot: .primary, address: $0.key), $0.value)
            }),
            // Mach-O signature/imports/dylibs projected at load time (nil for non-Mach-O / reload).
            machOMetadata: loaded.machOMetadata
        )

        // If the user declared MANUAL switch hints, the auto CFG above missed those switch
        // successors. Rebuild the CFG from the hint-merged tables so the basic-block graph
        // agrees with the decompiler's hint-aware switch reconstruction (both use
        // `resolvedJumpTables()`, which now resolves hints through the section-accurate
        // `hexByteReader`). No hints -> this guard skips the rebuild (byte-identical).
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.switchHints)
        }
        try checkAnalysisCheckpoint(.switchHints, cancellation: cancellation)
        if overrides.values.contains(where: { !($0.switchHint?.isEmpty ?? true) }) {
            let merged = snapshot.resolvedJumpTables(in: snapshot.primarySlot)
            let mergedBlocks = buildBasicBlocks(
                from: codeInstructions, functions: functions,
                codeStart: codeSection?.address, jumpTables: merged,
                noReturnTargets: noReturnTargets
            )
            snapshot.basicBlocks = mergedBlocks
            snapshot.controlFlowEdges = buildControlFlowEdges(
                from: codeInstructions, basicBlocks: mergedBlocks, jumpTables: merged,
                noReturnTargets: noReturnTargets
            )
        }
        work?.close(.cfg)

        // Derive the analysis-level diagnostics from the FULLY-built snapshot (after any
        // hint-aware CFG rebuild above), so the Problems panel reports against the same
        // edges/xrefs/sections the rest of the UI shows. Purely derived + recomputed on
        // every analyze; never persisted.
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.crossChecks)
        }
        try checkAnalysisCheckpoint(.diagnostics, cancellation: cancellation)
        let crossCheck = try MacScopePerformance.measure("Analysis.crossChecks") {
            try parserCrossCheckOutcome(for: loaded, cancellation: cancellation)
        }
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.collector)
        }
        snapshot.diagnostics = AnalysisDiagnosticsCollector().collect(
            AnalysisDiagnosticsCollector.Input(
                instructions: snapshot.instructions,
                controlFlowEdges: snapshot.controlFlowEdges,
                xrefs: snapshot.xrefs,
                sections: snapshot.sections,
                loaderTruncations: loaded.diagnosticTruncations.map {
                    AnalysisDiagnosticsCollector.LoaderTruncation(address: $0.address, message: $0.message)
                },
                parserDisagreements: crossCheck.disagreements,
                parserCrossCheckSkip: crossCheck.skip,
                loaderFindings: loaded.loaderFindings,
                work: work
            )
        )
        work?.close(.collector)
        if let attribution {
            attribution.close(currentSpan, outcome: .success)
            currentSpan = attribution.open(.fingerprint)
        }
        if let imageAnalysis = snapshot.analysis(in: image.slot) {
            snapshot.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
                binary: image,
                analysis: imageAnalysis, attribution: attribution
            )
        }
        attributionOutcome = .success
        return snapshot
        } catch {
            if attribution != nil && error is AnalysisCancelled { attributionOutcome = .cancelled }
            throw error
        }
    }

    /// Use the boundary-decoded snapshot directly. Reopening the transferred descriptor here
    /// would allow a second read to differ from the bytes retained in the persisted analysis.
    /// Custom loaders and path-dependent containers retain their existing scratch-file fallback.
    private func loadRehydrateBytes(_ bytes: Data, requestedSliceIndex: Int?,
                                    coffSectionLayoutVersion: Int?, cancellation: AnalysisCancellationToken) throws -> LoadedBinary {
        let version = coffSectionLayoutVersion
            ?? BinaryLoadSelection.legacyCOFFRehydrateLayoutVersion(for: bytes)
        let loader: any BinaryLoader = requestedSliceIndex == nil && version == nil
            ? self.loader
            : BinaryLoaderRouter(selection: BinaryLoadSelection(requestedMachOSliceIndex: requestedSliceIndex,
                coffSectionLayoutVersion: version))
        let sourceURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("macscope-rehydrate-\(UUID().uuidString)")
        if let byteLoader = loader as? any CapturedByteBinaryLoader,
           let loaded = try byteLoader.loadCapturedBytes(bytes, sourceURL: sourceURL, cancellation: cancellation) {
            return loaded
        }
        try cancellation.check(.rehydrate)
        try bytes.write(to: sourceURL)
        defer { try? FileManager.default.removeItem(at: sourceURL) }
        return try loader.load(at: sourceURL, cancellation: cancellation)
    }

    /// WS-5 rehydration: reconstruct an image's byte-derived products from its persisted slice
    /// `imageBytes` WITHOUT redoing disassembly or function discovery. `preserving` carries the
    /// products loaded from persistence (functions/instructions/xrefs/basicBlocks/controlFlowEdges/
    /// sourceLines/…); those are returned untouched. Only the loader-derived products (sections,
    /// relocations, Mach-O metadata, ObjC/Swift metadata, selectors), plus `jumpTables` (resolved
    /// from the persisted instructions) and `diagnostics` (recomputed), are rebuilt — exactly what a
    /// fresh `analyze()` would produce for those fields. The persisted `imageBytes` is a
    /// self-contained thin slice, so it loads directly (no slice index needed).
    func rehydrate(imageBytes: Data, requestedSliceIndex: Int?, preserving persisted: ImageAnalysis,
                   cancellation: AnalysisCancellationToken) throws -> ImageAnalysis {
        try rehydrate(imageBytes: imageBytes, requestedSliceIndex: requestedSliceIndex,
                      preserving: persisted, overrides: [:], cancellation: cancellation)
    }

    /// Rebuild derived table reads from the same image-local edits that produced the
    /// persisted instruction stream. The raw persisted attachment is still immutable.
    func rehydrate(imageBytes: Data, requestedSliceIndex: Int?, preserving persisted: ImageAnalysis,
                   overrides: [UInt64: AddressOverride],
                   cancellation: AnalysisCancellationToken) throws -> ImageAnalysis {
        try rehydrate(imageBytes: imageBytes, requestedSliceIndex: requestedSliceIndex,
            preserving: persisted, overrides: overrides,
            coffSectionLayoutVersion: BinaryLoadSelection.legacyCOFFRehydrateLayoutVersion(for: imageBytes),
            cancellation: cancellation)
    }

    func rehydrate(imageBytes: Data, requestedSliceIndex: Int?, preserving persisted: ImageAnalysis,
                   overrides: [UInt64: AddressOverride], coffSectionLayoutVersion: Int?,
                   cancellation: AnalysisCancellationToken) throws -> ImageAnalysis {
        let products = try rehydrateLoaderProducts(imageBytes: imageBytes,
            requestedSliceIndex: requestedSliceIndex, requestID: UUID(),
            coffSectionLayoutVersion: coffSectionLayoutVersion, cancellation: cancellation)
        return try RehydrationDerivedProducts.rebuild(persisted: persisted, loader: products,
            imageBytes: imageBytes, overrides: overrides, cancellation: cancellation)
    }

    /// Worker-only parsing seam. Does not receive or inspect persisted instruction/CFG products.
    func rehydrateLoaderProducts(imageBytes: Data, requestedSliceIndex: Int?, requestID: UUID,
                                 cancellation: AnalysisCancellationToken) throws -> RehydrationLoaderProducts {
        try rehydrateLoaderProducts(imageBytes: imageBytes, requestedSliceIndex: requestedSliceIndex,
            requestID: requestID,
            coffSectionLayoutVersion: BinaryLoadSelection.legacyCOFFRehydrateLayoutVersion(for: imageBytes),
            cancellation: cancellation)
    }

    func rehydrateLoaderProducts(imageBytes: Data, requestedSliceIndex: Int?, requestID: UUID,
                                 coffSectionLayoutVersion: Int?,
                                 cancellation: AnalysisCancellationToken) throws -> RehydrationLoaderProducts {
        guard coffSectionLayoutVersion == nil || coffSectionLayoutVersion == 0 || coffSectionLayoutVersion == 1 else {
            throw BinaryLoadSelectionError.invalidCOFFSectionLayoutVersion
        }
        try cancellation.check(.rehydrate)
        let loaded = try loadRehydrateBytes(imageBytes, requestedSliceIndex: requestedSliceIndex,
            coffSectionLayoutVersion: coffSectionLayoutVersion, cancellation: cancellation)
        try validateSelectedSliceRange(of: loaded)
        var products = rehydrationLoaderProducts(from: loaded, requestedSliceIndex: requestedSliceIndex,
                                                 requestID: requestID)
        let crossCheck = try parserCrossCheckOutcome(for: loaded, cancellation: cancellation)
        products.parserDisagreements = crossCheck.disagreements
        products.parserCrossCheckSkip = crossCheck.skip
        try products.validate(imageByteCount: imageBytes.count)
        try cancellation.check(.rehydrate)
        return products
    }

    /// Projection only; all byte and layout evidence originates in LoadedBinary.
    private func rehydrationLoaderProducts(from loaded: LoadedBinary, requestedSliceIndex: Int?,
                                            requestID: UUID) -> RehydrationLoaderProducts {
        var products = RehydrationLoaderProducts(requestID: requestID,
            requestedSliceIndex: requestedSliceIndex, imageByteCount: loaded.bytes.count,
            sliceOffset: loaded.sliceOffset, sliceSize: loaded.sliceSize,
            sections: loaded.sections.map {
                SectionSummary(id: UUID(), name: $0.name, address: $0.address, size: $0.size,
                    fileOffset: $0.fileOffset, isExecutable: $0.isExecutable,
                    isZeroFill: $0.isZeroFill, fileSize: $0.fileSize, coffCoordinate: $0.coffCoordinate,
                    containsCStringLiterals: $0.containsCStringLiterals)
            }, mappings: makeByteMappings(loaded: loaded))
        products.preferredSegmentLayout = loaded.preferredSegmentLayout
        products.codeDataRanges = loaded.codeDataRanges.map {
            CodeDataRangeSummary(id: UUID(), address: $0.address, size: $0.size, kind: $0.kind)
        }
        products.relocations = loaded.relocations
        products.identityEffectiveByteRanges = loaded.identityEffectiveByteRanges
        products.machOMetadata = loaded.machOMetadata
        products.objcClasses = loaded.objcClasses
        products.objcCategories = loaded.objcCategories
        products.objcProtocols = loaded.objcProtocols
        products.swiftTypes = loaded.swiftTypes
        products.swiftConformances = loaded.swiftConformances
        products.objcSelectors = loaded.objcSelectors
        products.constantCFStrings = loaded.constantCFStrings
        products.cfStringBackings = loaded.cfStringBackings
        products.objcClassReferences = loaded.objcClassReferences
        products.loaderTruncations = loaded.diagnosticTruncations.map {
            AnalysisDiagnosticsCollector.LoaderTruncation(address: $0.address, message: $0.message)
        }
        products.loaderFindings = loaded.loaderFindings
        return products
    }


    /// Resolves jump-table case targets from the decoded instruction rows using a
    /// byte reader backed by the loaded binary's section bytes. Returns an empty
    /// dictionary whenever there is no executable text section or nothing
    /// resolves — keeping the snapshot indistinguishable from today's output.
    private func resolveJumpTables(
        instructionRows: [InstructionRow], loaded: LoadedBinary,
        functions: [FunctionSummary], patchOverlay: BytePatchOverlay,
        byteMappings: [FileAddressMapping], cancellation: AnalysisCancellationToken
    ) throws -> [UInt64: [UInt64]] {
        let work = self.work
        let products = RehydrationLoaderProducts(requestID: UUID(), requestedSliceIndex: nil,
            imageByteCount: loaded.bytes.count, sliceOffset: loaded.sliceOffset, sliceSize: loaded.sliceSize,
            sections: loaded.sections.map {
                SectionSummary(id: UUID(), name: $0.name, address: $0.address, size: $0.size,
                    fileOffset: $0.fileOffset, isExecutable: $0.isExecutable,
                    isZeroFill: $0.isZeroFill, fileSize: $0.fileSize, coffCoordinate: $0.coffCoordinate,
                    containsCStringLiterals: $0.containsCStringLiterals)
            }, mappings: byteMappings, preferredSegmentLayout: loaded.preferredSegmentLayout)
        return try RehydrationDerivedProducts.resolveJumpTables(instructionRows: instructionRows,
            imageBytes: loaded.bytes, loader: products, functions: functions,
            patchOverlay: patchOverlay, byteMappings: byteMappings, cancellation: cancellation,
            work: work)
    }

    /// Returns only bytes for which the loader established physical file authority.
    /// Formats such as ELF and PE distinguish a virtual memory span from its raw-file prefix;
    /// callers must never decode or interpret the zero-filled tail as if bytes existed on disk.
    /// "Objective C implementation of -[Class selector]" for each recovered method IMP that has no
    /// symbol at its address (a symbolled IMP already says what it is). Categories render as
    /// `-[Class(Category) selector]`. An IMP shared by several methods lists each, sorted, so the
    /// result is deterministic.
    static func objcImplementationComments(
        classes: [ObjCClass],
        categories: [ObjCCategory],
        namedAddresses: Set<UInt64>
    ) -> [UInt64: String] {
        var owners: [UInt64: Set<String>] = [:]
        func add(_ methods: [ObjCMethod], owner: String) {
            for method in methods {
                guard let imp = method.implementation, imp != 0, !namedAddresses.contains(imp) else { continue }
                owners[imp, default: []].insert("\(method.isClassMethod ? "+" : "-")[\(owner) \(method.selector)]")
            }
        }
        for cls in classes {
            add(cls.instanceMethods, owner: cls.name)
            add(cls.classMethods, owner: cls.name)
        }
        for category in categories {
            let owner = "\(category.className)(\(category.name))"
            add(category.instanceMethods, owner: owner)
            add(category.classMethods, owner: owner)
        }
        return owners.mapValues { "Objective C implementation of " + $0.sorted().joined(separator: ", ") }
    }

    struct ObjCMethodNameProjection: Equatable {
        var functions: [FunctionSummary]
        var symbols: [SymbolSummary]
        var abstentions: ObjCMethodNameAbstentions
    }

    struct ObjCMethodNameAbstentions: Equatable {
        var duplicateFunctionStart: Int = 0
        var notFallbackName: Int = 0
        var alreadyNamed: Int = 0
        var sharedImplementation: Int = 0
        var textNotUnique: Int = 0
        var existingNameCollision: Int = 0
    }

    /// Projects only exact, unshared IMPs onto generated fallback names.
    /// Count each candidate function once, in duplicate-start, non-fallback, named,
    /// shared-implementation, nonunique-text, existing-name order. Existing names
    /// and user display overrides retain precedence. New symbol IDs are provisional;
    /// analyze assigns stable IDs after combining all symbol sources. Determinism
    /// covers names, addresses, provenance and counts, excluding provisional symbol IDs.
    static func projectObjCMethodNames(
        functions: [FunctionSummary], classes: [ObjCClass], categories: [ObjCCategory],
        namedAddresses: Set<UInt64>, existingNames: [String]
    ) -> ObjCMethodNameProjection {
        func nameKey(_ value: String) -> String {
            let stripped = value.hasPrefix("_") ? String(value.dropFirst()) : value
            let name = stripped.isEmpty ? value : stripped
            return name.folding(options: .caseInsensitive, locale: nil)
        }

        let audit = auditObjCMethodImplementations(
            functions: functions, classes: classes, categories: categories, sections: [])
        var textsByIMP: [UInt64: Set<String>] = [:]
        for row in audit.rows
        where row.mismatch == nil && row.containingFunction?.start == row.implementation {
            textsByIMP[row.implementation, default: []].insert(row.method)
        }
        var functionCounts: [UInt64: Int] = [:]
        for function in functions { functionCounts[function.startAddress, default: 0] += 1 }
        var startsByTextKey: [String: Set<UInt64>] = [:]
        for (imp, texts) in textsByIMP {
            for text in texts { startsByTextKey[nameKey(text), default: []].insert(imp) }
        }
        let occupied = Set((existingNames + functions.map(\.name)).map(nameKey))
        var projected = functions
        var symbols: [SymbolSummary] = []
        var abstentions = ObjCMethodNameAbstentions()
        for index in functions.indices {
            let function = functions[index]
            let start = function.startAddress
            guard let texts = textsByIMP[start], !texts.isEmpty else { continue }
            guard functionCounts[start] == 1 else {
                abstentions.duplicateFunctionStart += 1
                continue
            }
            guard function.name == "sub_\(start.hexAddress)" else {
                abstentions.notFallbackName += 1
                continue
            }
            guard !namedAddresses.contains(start) else {
                abstentions.alreadyNamed += 1
                continue
            }
            guard texts.count == 1, let text = texts.first else {
                abstentions.sharedImplementation += 1
                continue
            }
            let key = nameKey(text)
            guard startsByTextKey[key]?.count == 1 else {
                abstentions.textNotUnique += 1
                continue
            }
            guard !occupied.contains(key) else {
                abstentions.existingNameCollision += 1
                continue
            }
            projected[index].name = text
            symbols.append(SymbolSummary(id: UUID(), name: text, address: start,
                                         kind: "objc-method", libraryName: nil))
        }
        symbols.sort { ($0.address ?? 0) < ($1.address ?? 0) }
        return ObjCMethodNameProjection(functions: projected, symbols: symbols, abstentions: abstentions)
    }

    struct ObjCIMPAuditFunction: Equatable {
        var start: UInt64
        var end: UInt64
        var name: String
    }

    enum ObjCIMPAuditMismatch: Equatable {
        case notInAnyFunction
        case insideFunction(offset: UInt64)
    }

    struct ObjCIMPAuditRow: Equatable {
        var implementation: UInt64
        var method: String
        var containingFunction: ObjCIMPAuditFunction?
        var mismatch: ObjCIMPAuditMismatch?
        /// Count method entries, not distinct display names; sharing is independent of mismatch.
        var sharedBy: Int
    }

    enum ObjCIMPContainerIssue: String, Equatable {
        case sectionMetadataMissing
        case partialPointerSlot
        case entryCountOverflow
        case parsedCountShortfall
        case parsedCountExceedsSlots
    }

    struct ObjCIMPContainerCoverage: Equatable {
        var section: String
        var sectionCount: Int
        /// Sum of size / 8 across sections of this kind; nil if absent or unrepresentable.
        var declaredEntries: UInt64?
        var parsedContainers: Int
        var issues: [ObjCIMPContainerIssue]
    }

    struct ObjCIMPAudit: Equatable {
        var rows: [ObjCIMPAuditRow]
        var containers: [ObjCIMPContainerCoverage]
        var invalidFunctionExtents: Int
    }

    /// Read-only W2 comparison. This audit never substitutes a method text for a function name;
    /// projectObjCMethodNames alone projects exact, unshared, unsymbolled starts, subject to its abstention rules.
    /// Exact starts win; overlapping containers otherwise choose the lowest start, then input order.
    /// Coverage counts pointer slots, not proven non-null entities or successfully parsed methods.
    /// ObjCClassParser reads only the first section of each name and caps entries at maxClasses (ObjCClassParser.swift:116-118, :170-172), so a shortfall can also be parser scope.
    static func auditObjCMethodImplementations(
        functions: [FunctionSummary], classes: [ObjCClass], categories: [ObjCCategory],
        sections: [SectionSummary]
    ) -> ObjCIMPAudit {
        var methods: [(implementation: UInt64, text: String)] = []
        var sharing: [UInt64: Int] = [:]
        func append(_ entries: [ObjCMethod], owner: String) {
            for method in entries {
                guard let imp = method.implementation, imp != 0 else { continue }
                methods.append((imp, "\(method.isClassMethod ? "+" : "-")[\(owner) \(method.selector)]"))
                sharing[imp, default: 0] += 1
            }
        }
        for cls in classes {
            append(cls.instanceMethods, owner: cls.name)
            append(cls.classMethods, owner: cls.name)
        }
        for category in categories {
            let owner = "\(category.className)(\(category.name))"
            append(category.instanceMethods, owner: owner)
            append(category.classMethods, owner: owner)
        }

        let valid = functions.indices.filter { functions[$0].endAddress >= functions[$0].startAddress }
        let ordered = valid.sorted {
            let left = functions[$0].startAddress
            let right = functions[$1].startAddress
            return left == right ? $0 < $1 : left < right
        }
        var exact: [UInt64: Int] = [:]
        var maximumEnds: [UInt64] = []
        maximumEnds.reserveCapacity(ordered.count)
        for index in ordered {
            let function = functions[index]
            if exact[function.startAddress] == nil { exact[function.startAddress] = index }
            maximumEnds.append(max(maximumEnds.last ?? 0, function.endAddress))
        }
        func containing(_ address: UInt64) -> Int? {
            if let index = exact[address] { return index }
            var low = 0
            var high = ordered.count
            while low < high {
                let middle = low + (high - low) / 2
                if functions[ordered[middle]].startAddress <= address { low = middle + 1 }
                else { high = middle }
            }
            let upper = low
            guard upper > 0, maximumEnds[upper - 1] > address else { return nil }
            low = 0
            high = upper
            while low < high {
                let middle = low + (high - low) / 2
                if maximumEnds[middle] > address { high = middle }
                else { low = middle + 1 }
            }
            return ordered[low]
        }

        let rows: [ObjCIMPAuditRow] = methods.map { entry in
            guard let index = containing(entry.implementation) else {
                return ObjCIMPAuditRow(implementation: entry.implementation, method: entry.text,
                    containingFunction: nil, mismatch: .notInAnyFunction,
                    sharedBy: sharing[entry.implementation] ?? 1)
            }
            let function = functions[index]
            let offset = entry.implementation - function.startAddress
            return ObjCIMPAuditRow(implementation: entry.implementation, method: entry.text,
                containingFunction: ObjCIMPAuditFunction(start: function.startAddress,
                    end: function.endAddress, name: function.name),
                mismatch: offset == 0 ? nil : .insideFunction(offset: offset),
                sharedBy: sharing[entry.implementation] ?? 1)
        }

        func coverage(_ name: String, parsed: Int) -> ObjCIMPContainerCoverage {
            let selected = sections.filter { $0.name.split(separator: ",").last.map(String.init) == name }
            guard !selected.isEmpty else {
                return ObjCIMPContainerCoverage(section: name, sectionCount: 0, declaredEntries: nil,
                    parsedContainers: parsed, issues: [.sectionMetadataMissing])
            }
            var count: UInt64 = 0
            var overflow = false
            var partial = false
            for section in selected {
                partial = partial || section.size % 8 != 0
                let next = count.addingReportingOverflow(section.size / 8)
                if next.overflow { overflow = true }
                if !overflow { count = next.partialValue }
            }
            var issues: [ObjCIMPContainerIssue] = []
            if partial { issues.append(.partialPointerSlot) }
            if overflow { issues.append(.entryCountOverflow) }
            else if UInt64(parsed) < count { issues.append(.parsedCountShortfall) }
            else if UInt64(parsed) > count { issues.append(.parsedCountExceedsSlots) }
            return ObjCIMPContainerCoverage(section: name, sectionCount: selected.count,
                declaredEntries: overflow ? nil : count, parsedContainers: parsed, issues: issues)
        }
        return ObjCIMPAudit(rows: rows, containers: [
            coverage("__objc_classlist", parsed: classes.count),
            coverage("__objc_catlist", parsed: categories.count)
        ], invalidFunctionExtents: functions.count - valid.count)
    }

    /// `_objc_msgSend$<selector>` names for the entries of `__objc_stubs` (ARM64 only), so a stripped
    /// binary's `bl <objc stub>` call sites label as message sends instead of bare addresses.
    static func objcStubSelectorNames(in loaded: LoadedBinary) -> [UInt64: String] {
        guard loaded.cpuType == MachOConstants.cpuTypeARM64, !loaded.objcSelectors.isEmpty,
              let section = loaded.sections.first(where: {
                  $0.name.split(separator: ",").last == "__objc_stubs" && !$0.isZeroFill
              }) else { return [:] }
        guard let count = Int(exactly: min(section.size, section.fileSize ?? section.size)),
              count > 0,
              let bytes = fileBackedBytes(in: loaded, section: section, relativeOffset: 0, count: count) else {
            return [:]
        }
        var symbolGroups: [UInt64: [SymbolSummary]] = [:]
        for symbol in loaded.symbols {
            if let address = symbol.address { symbolGroups[address, default: []].append(symbol) }
        }
        let slotGroups = Dictionary(grouping: loaded.indirectSymbols, by: \.address)
        func hasUnambiguousMessageSendName(_ address: UInt64) -> Bool {
            let symbols = symbolGroups[address] ?? []
            let slots = slotGroups[address] ?? []
            return symbols.allSatisfy { ($0.rawLinkageName ?? $0.name) == "_objc_msgSend" }
                && slots.allSatisfy { !$0.isLocal && !$0.isAbsolute && $0.symbolName == "_objc_msgSend" }
        }
        return ObjCStubSelectorRecovery.names(
            stubBytes: bytes,
            sectionAddress: section.address,
            selectorBySelrefAddress: loaded.objcSelectors,
            messageSendTargets: Set(loaded.symbols.compactMap {
                guard let address = $0.address, hasUnambiguousMessageSendName(address) else { return nil }
                return address
            }).union(loaded.indirectSymbols.filter {
                hasUnambiguousMessageSendName($0.address)
                    && ["__stubs", "__auth_stubs"].contains(String($0.sourceSection.split(separator: ",").last ?? ""))
            }.map(\.address)),
            messageSendPointerSlots: Set(loaded.indirectSymbols.filter {
                hasUnambiguousMessageSendName($0.address)
                    && ["__got", "__auth_got", "__la_symbol_ptr", "__nl_symbol_ptr"]
                        .contains(String($0.sourceSection.split(separator: ",").last ?? ""))
            }.map(\.address))
        )
    }

    static func fileBackedBytes(
        in loaded: LoadedBinary,
        section: BinarySection,
        relativeOffset: UInt64,
        count: Int
    ) -> Data? {
        guard count > 0, !section.isZeroFill else { return nil }
        let physicalSize = min(section.size, section.fileSize ?? section.size)
        guard relativeOffset <= physicalSize,
              UInt64(count) <= physicalSize - relativeOffset else { return nil }
        let (fileRelative, fileOverflow) = section.fileOffset.addingReportingOverflow(relativeOffset)
        guard !fileOverflow else { return nil }
        let (absolute, absoluteOverflow) = loaded.sliceOffset.addingReportingOverflow(fileRelative)
        guard !absoluteOverflow, absolute <= UInt64(Int.max),
              let base = Int(exactly: absolute), base <= loaded.bytes.count - count else { return nil }
        if let sliceSize = loaded.sliceSize {
            guard fileRelative <= sliceSize, UInt64(count) <= sliceSize - fileRelative else { return nil }
        }
        return loaded.bytes.subdata(in: base..<(base + count))
    }

    static func previewSnapshot() -> WorkspaceSnapshot {
        let image = BinaryImage(
            id: UUID(),
            name: "MacScope Sample Binary",
            path: "/Applications/Sample.app",
            kind: "synthetic arm64 fixture",
            architecture: "arm64"
        )

        let functions = [
            FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000_00000, endAddress: 0x1000_00028, confidence: 0.92),
            FunctionSummary(id: UUID(), name: "_analyze_macho", startAddress: 0x1000_01000, endAddress: 0x1000_01240, confidence: 0.71),
            FunctionSummary(id: UUID(), name: "_render_listing", startAddress: 0x1000_02000, endAddress: 0x1000_02380, confidence: 0.66)
        ]

        let rows = [
            InstructionRow(address: 0x1000_00000, bytes: "ff 83 00 d1", mnemonic: "sub", operands: "sp, sp, #0x20", hasBreakpoint: false, comment: "Stack frame"),
            InstructionRow(address: 0x1000_00004, bytes: "fd 7b 01 a9", mnemonic: "stp", operands: "x29, x30, [sp, #0x10]", hasBreakpoint: true, comment: nil),
            InstructionRow(address: 0x1000_00008, bytes: "fd 43 00 91", mnemonic: "add", operands: "x29, sp, #0x10", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1000_0000c, bytes: "08 00 00 90", mnemonic: "adrp", operands: "x8, 0x100002000", hasBreakpoint: false, comment: "Page-relative address"),
            InstructionRow(address: 0x1000_00010, bytes: "00 01 40 f9", mnemonic: "ldr", operands: "x0, [x8]", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1000_00014, bytes: "05 00 00 94", mnemonic: "bl", operands: "_analyze_macho", hasBreakpoint: false, comment: "Call analysis entry"),
            InstructionRow(address: 0x1000_00018, bytes: "00 00 80 52", mnemonic: "mov", operands: "w0, #0", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1000_0001c, bytes: "fd 7b 41 a9", mnemonic: "ldp", operands: "x29, x30, [sp, #0x10]", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1000_00020, bytes: "ff 83 00 91", mnemonic: "add", operands: "sp, sp, #0x20", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1000_00024, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil)
        ]

        // The fixture is a pure code blob whose first byte sits at the first instruction's
        // virtual address — so it carries a single faithful __text section + `imageBytes`,
        // giving the hex pane a real verified mapping (offset 0 -> 0x1_0000_0000) instead of
        // relying on the removed linear-anchoring guess.
        let codeBytes = Data(rows.flatMap { Self.bytes(from: $0.bytes) })
        let textSection = SectionSummary(
            id: UUID(), name: "__TEXT,__text", address: 0x1000_00000,
            size: UInt64(codeBytes.count), fileOffset: 0, isExecutable: true
        )

        return WorkspaceSnapshot(
            binaries: [image],
            functions: functions,
            basicBlocks: [
                BasicBlockSummary(id: UUID(), functionID: functions[0].id, startAddress: 0x1000_00000, endAddress: 0x1000_00028, instructionCount: rows.count),
                BasicBlockSummary(id: UUID(), functionID: functions[1].id, startAddress: 0x1000_01000, endAddress: 0x1000_01240, instructionCount: 18),
                BasicBlockSummary(id: UUID(), functionID: functions[2].id, startAddress: 0x1000_02000, endAddress: 0x1000_02380, instructionCount: 24)
            ],
            instructions: rows,
            xrefs: [
                XRef(id: UUID(), from: 0x1000_00014, to: 0x1000_01000, kind: "call"),
                XRef(id: UUID(), from: 0x1000_02020, to: 0x1000_00000, kind: "reference")
            ],
            // Control-flow edges start at a decoded instruction (every engine producer emits
            // them from `instruction.address`, and HS-1 reopen repair enforces it). The
            // 0x1000_02020 -> _main reference is a data-flow xref only: _render_listing has no
            // saved instruction rows in this fixture, so it is not a control-flow edge.
            controlFlowEdges: [
                ControlFlowEdge(id: UUID(), from: 0x1000_00014, to: 0x1000_01000, kind: "call")
            ],
            hexBytes: codeBytes,
            sections: [textSection],
            imageBytes: codeBytes
        )
    }

    /// Identity-complete form of the bounded preview fixture used only by the explicit installed
    /// DCP05C qualification launch. The ordinary preview intentionally remains lightweight; this
    /// variant derives every native-request authority field from the exact synthetic bytes so the
    /// installed app exercises the production projection, admission, XPC, and command surfaces.
    static func nativeDecompilerQualificationSnapshot() -> WorkspaceSnapshot {
        var snapshot = previewSnapshot()
        guard var binary = snapshot.binaries.first,
              var analysis = snapshot.analysis(in: binary.slot),
              !analysis.imageBytes.isEmpty
        else { return snapshot }

        do {
            // The governed AArch64 provider performs bounded instruction lookahead beyond the
            // requested function interval. Keep that auxiliary byte authority explicit: the
            // function remains the original 40-byte _main, while the selected slice maps another
            // 64 caller-owned bytes containing only canonical AArch64 NOP instructions.
            let functionByteCount = analysis.imageBytes.count
            let mappedLookaheadByteCount = 64
            let nop = Data([0x1f, 0x20, 0x03, 0xd5])
            precondition(mappedLookaheadByteCount.isMultiple(of: nop.count))
            for _ in 0..<(mappedLookaheadByteCount / nop.count) {
                analysis.imageBytes.append(nop)
            }
            analysis.hexBytes = Data(
                analysis.imageBytes.prefix(WorkspaceSnapshot.hexViewByteWindow)
            )
            guard analysis.functions.first?.endAddress
                    == 0x1000_00000 + UInt64(functionByteCount),
                  analysis.sections.count == 1
            else {
                throw NativeDecompilerQualificationFixtureError.invalidFunctionOrSection
            }
            analysis.sections[0].size = UInt64(analysis.imageBytes.count)
            analysis.sections[0].fileSize = UInt64(analysis.imageBytes.count)

            let byteCount = UInt64(analysis.imageBytes.count)
            let digest = AnalysisFingerprintBuilder.sha256Hex(analysis.imageBytes)
            let artifact = try MachOSliceArtifactIdentity(
                uuid: UUID(uuidString: "d0c05c00-0000-4000-8000-000000000001"),
                rawCPUType: MachOConstants.cpuTypeARM64,
                rawCPUSubtype: 0,
                selectedSliceSHA256: digest,
                selectedSliceByteCount: byteCount
            )
            let layout = try MachOPreferredSegmentLayout(
                records: [
                    .init(
                        name: "__TEXT",
                        preferredVMStart: 0x1000_00000,
                        preferredVMSize: byteCount,
                        sliceRelativeFileOffset: 0,
                        fileSize: byteCount,
                        initialProtections: 5
                    ),
                ],
                selectedSliceByteCount: byteCount
            )
            binary.artifactIdentity = artifact
            binary.preferredSegmentLayout = layout
            binary.artifactIntegrityState = .verified
            analysis.identityEffectiveByteRanges = [
                try IdentityEffectiveByteRangeAttestation(
                    artifactIdentity: artifact,
                    segmentName: "__TEXT",
                    startAddress: 0x1000_00000,
                    endAddressExclusive: 0x1000_00000 + byteCount,
                    sliceRelativeFileOffset: 0,
                    byteCount: byteCount,
                    initialProtections: 5,
                    rawBytesSHA256: digest
                ),
            ]
            analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
                binary: binary,
                analysis: analysis
            )
            snapshot.binaries[0] = binary
            snapshot.analysisBySlot[binary.slot] = analysis
        } catch {
            assertionFailure("The sealed native-decompiler qualification fixture is invalid: \(error)")
        }
        return snapshot
    }

    private enum NativeDecompilerQualificationFixtureError: Error {
        case invalidFunctionOrSection
    }

    private static func bytes(from byteText: String) -> [UInt8] {
        byteText.split(separator: " ").compactMap { UInt8($0, radix: 16) }
    }

    /// Gathers recovered class and category IMPs as candidate function starts.
    /// Pure collection: `validatedMetadataStarts` remains the trust boundary.
    private func objcMethodImplementations(from objcClasses: [ObjCClass],
                                          categories: [ObjCCategory]) -> Set<UInt64> {
        Set(objcClasses.flatMap { ($0.instanceMethods + $0.classMethods).compactMap(\.implementation) })
            .union(categories.flatMap { ($0.instanceMethods + $0.classMethods).compactMap(\.implementation) })
    }

    /// Decides which candidate Objective-C method IMPs are trustworthy enough to promote to a
    /// function boundary in `makeFunctionSummaries`.
    ///
    /// This is the conservatism policy for metadata-seeded discovery. The inputs:
    ///   - `candidates`: raw IMP virtual addresses from the ObjC metadata (untrusted-binary-derived).
    ///   - `codeStart` / `codeEnd`: the executable text range (`nil` if unknown).
    ///   - `decodedInstructionAddresses`: every address the linear sweep actually decoded as an
    ///     instruction start.
    ///   - `dataAddresses`: addresses the user/heuristics marked as DATA (never a function boundary).
    ///
    /// The tension: an IMP is an *explicit runtime code pointer*, so it is high-confidence — and the
    /// whole point is to recover IMPs the linear sweep MISSED (so requiring membership in
    /// `decodedInstructionAddresses` would defeat the feature). But a malformed binary could point an
    /// IMP mid-instruction, into a stub, or outside text, which would seed a misaligned phantom
    /// function. A missed start silently merges two functions; a false start silently splits one —
    /// both are bad.
    ///
    /// Policy: trust the metadata within the text range, drop data-marked addresses, and apply an
    /// architecture-aware alignment guard. Deliberately does NOT require membership in
    /// `decodedInstructionAddresses` — that is exactly the IMP set the linear sweep missed and this
    /// feature exists to recover.
    private func validatedMetadataStarts(
        candidates: Set<UInt64>,
        codeStart: UInt64?,
        codeEnd: UInt64?,
        decodedInstructionAddresses: Set<UInt64>,
        dataAddresses: Set<UInt64>
    ) -> Set<UInt64> {
        candidates.filter { address in
            // Must lie inside the executable text range (when known): an IMP outside text belongs to
            // another image or is a bind, not a function body in this binary.
            if let codeStart, let codeEnd, !(address >= codeStart && address < codeEnd) { return false }
            // Respect data overrides — never seed a function at a user/heuristic-marked data address.
            if dataAddresses.contains(address) { return false }
            // Garbage guard: ARM64 instructions are 4-byte aligned, so a misaligned IMP is malformed
            // metadata. x86 has no alignment guarantee, so there only reject a misaligned IMP the
            // linear sweep did NOT independently decode (a real x86 IMP it decoded is trustworthy).
            if address % 4 != 0 && !decodedInstructionAddresses.contains(address) { return false }
            return true
        }
    }

    /// Test-only access to the private implementation, with zero-budget reference fallback.
    func functionSummariesForTesting(
        from loaded: LoadedBinary, codeSection: BinarySection?,
        decodedInstructions: [DecodedInstruction], dataAddresses: Set<UInt64> = [],
        procedureAddresses: Set<UInt64> = [], noReturnTargets: Set<UInt64> = [],
        preparation: DiscoveryPreparationStore, sectionOrdinal: Int = 0
    ) -> [FunctionSummary] {
        functionSummariesForTesting(from: loaded, codeSection: codeSection,
            rows: decodedInstructions[...], dataAddresses: dataAddresses,
            procedureAddresses: procedureAddresses, noReturnTargets: noReturnTargets,
            preparation: preparation, sectionOrdinal: sectionOrdinal)
    }

    func functionSummariesForTesting(
        from loaded: LoadedBinary, codeSection: BinarySection?,
        rows decodedInstructions: ArraySlice<DecodedInstruction>, dataAddresses: Set<UInt64> = [],
        procedureAddresses: Set<UInt64> = [], noReturnTargets: Set<UInt64> = [],
        preparation: DiscoveryPreparationStore, sectionOrdinal: Int = 0
    ) -> [FunctionSummary] {
        makeFunctionSummaries(from: loaded, codeSection: codeSection,
            decodedInstructions: decodedInstructions, dataAddresses: dataAddresses,
            procedureAddresses: procedureAddresses, noReturnTargets: noReturnTargets,
            preparation: preparation, sectionOrdinal: sectionOrdinal, discoveryOrdinal: 0)
    }

    private func makeFunctionSummaries(
        from loaded: LoadedBinary,
        codeSection: BinarySection?,
        decodedInstructions: ArraySlice<DecodedInstruction>,
        dataAddresses: Set<UInt64>,
        procedureAddresses: Set<UInt64>,
        noReturnTargets: Set<UInt64>,
        preparation: DiscoveryPreparationStore,
        sectionOrdinal: Int,
        discoveryOrdinal: Int
    ) -> [FunctionSummary] {
        let codeStart = codeSection?.address
        // Checked span: a section declaring address + size past UInt64.max leaves the
        // upper bound unknown rather than trapping, degrading to the existing
        // "code bounds unknown" path below without fabricating a wrapped low address.
        // A zero-size section keeps its historical empty range (rejects every start).
        let codeEnd = codeSection.flatMap { section -> UInt64? in
            if section.size == 0 { return section.address }
            return Range<UInt64>.validated(start: section.address, size: section.size)?.upperBound
        }
        var symbolNameByAddress: [UInt64: String] = [:]
        for symbol in loaded.symbols {
            guard let address = symbol.address else { continue }
            if symbolNameByAddress[address] == nil {
                symbolNameByAddress[address] = symbol.name
            }
        }
        work?.add(.symbolNameMapBuilds)

        let functionStartEntries = loaded.functionStarts
            .filter { address in
                guard let codeStart, let codeEnd else { return true }
                return address >= codeStart && address < codeEnd
            }
        work?.add(.sectionStartFilterBuilds)
        // Import-stub sections forward each entry (12 bytes in the arm64 fixture) to
        // one import. Seeding their first address creates a phantom function named
        // `__text` that swallows every stub rather than representing a function body.
        let entryStart = loaded.entryPointAddress.flatMap { address in
            guard let codeStart, let codeEnd, address >= codeStart, address < codeEnd else { return nil }
            return address
        } ?? (loaded.entryPointAddress == nil && !(codeSection.map { Self.isImportStubSection(named: $0.name) } ?? false) ? codeStart : nil)
        let seededStarts = Set(functionStartEntries + [entryStart].compactMap { $0 })
        let prepared: DiscoveryPreparation?
        let directCallTargets: Set<UInt64>
        do {
            let span = attribution?.open(.discoveryPrepare, ordinal: discoveryOrdinal)
            defer { attribution?.close(span, outcome: .success) }
            prepared = preparation.prepare(sectionOrdinal: sectionOrdinal,
                rows: decodedInstructions, codeStart: codeStart, codeEnd: codeEnd,
                existingStarts: seededStarts)
            if let baseline = prepared?.baselineDirectCalls {
                directCallTargets = baseline
                work?.begin(.preparationFallbackDirectCallRequests)
            } else {
                work?.add(.preparationFallbackDirectCallRequests)
                directCallTargets = directCallFunctionStarts(
                    from: decodedInstructions,
                    codeStart: codeStart,
                    codeEnd: codeEnd,
                    existingStarts: seededStarts
                )
            }
        }
        // Recursive-descent / worklist recovery of starts the linear LC_FUNCTION_STARTS
        // pass missed. A single MISSED start silently MERGES two adjacent functions in
        // the [start, nextStart) slicer, so recovering high-confidence boundaries here
        // is correctness-critical. Conservatism is paramount: a false split is as bad as
        // a false merge, so only addresses with TWO corroborating signals are promoted.
        let recoveredStarts = recoverFunctionStarts(
            from: decodedInstructions,
            codeStart: codeStart,
            codeEnd: codeEnd,
            existingStarts: seededStarts.union(directCallTargets),
            noReturnTargets: noReturnTargets
        )
        var startSet = seededStarts.union(directCallTargets).union(recoveredStarts)
        // A data-marked address is not a function boundary — drop it so the listing's
        // data region doesn't seed a spurious (empty-bodied) function.
        startSet.subtract(dataAddresses)
        // A user-forced procedure start (Mark as Procedure) wins over the heuristics —
        // but ONLY if it is a real decoded-instruction start (the same guard
        // `directCallFunctionStarts` uses). The scripting `make-procedure` command is
        // unvalidated, so without this a mid-instruction / past-end / out-of-text address
        // would seed a MISALIGNED or EMPTY phantom function and persist it. Requiring the
        // address to be in the data-filtered decoded set covers all of those at once (it
        // is already in executable text and not data-marked).
        let decodedInstructionAddresses: Set<UInt64>
        if let retained = prepared?.decodedAddresses {
            decodedInstructionAddresses = retained
            work?.begin(.preparationFallbackDecodedAddressBuilds)
        } else {
            work?.add(.preparationFallbackDecodedAddressBuilds)
            decodedInstructionAddresses = Set(decodedInstructions.map(\.address))
        }
        startSet.formUnion(procedureAddresses.filter { decodedInstructionAddresses.contains($0) })
        // Metadata-seeded discovery: every Objective-C method IMP is a guaranteed entry point. Many
        // are reachable ONLY through the runtime's dispatch tables — no static `bl` targets them — so
        // the linear sweep and direct-call recovery miss them. `validatedMetadataStarts` applies the
        // conservatism policy that decides which candidate IMPs are safe to promote to a boundary.
        let objcCandidates = objcMethodImplementations(from: loaded.objcClasses, categories: loaded.objcCategories)
        work?.add(.objcCandidateCollections)
        startSet.formUnion(validatedMetadataStarts(
            candidates: objcCandidates,
            codeStart: codeStart,
            codeEnd: codeEnd,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses
        ))
        // WS-9: Swift-metadata-seeded discovery — methods (class vtables), accessors, and protocol
        // witnesses are reached only through the runtime's descriptor tables, so the sweep and
        // direct-call recovery miss them on binaries without LC_FUNCTION_STARTS. Same conservatism
        // gate as the ObjC IMPs. `functionCandidates` is empty until the Task-3 extractor lands, so
        // this union is a no-op for now (byte-identical golden path).
        startSet.formUnion(validatedMetadataStarts(
            candidates: SwiftMetadataFunctionExtractor.functionCandidates(in: loaded, work: work),
            codeStart: codeStart,
            codeEnd: codeEnd,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses
        ))
        let symbolCandidates = symbolFunctionStartCandidates(in: loaded)
        work?.add(.symbolCandidateCollections)
        let symbolStartSet = validatedMetadataStarts(
            candidates: symbolCandidates,
            codeStart: codeStart,
            codeEnd: codeEnd,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses
        )
        startSet.formUnion(symbolStartSet)
        // Data code-pointer seeding: a rebase pointer stored in data that targets executable text
        // is (almost always) a function-pointer-table / vtable / dispatch-table entry — a function
        // reached ONLY indirectly, which the linear sweep, direct-call recovery, and PROLOGUE
        // recovery all miss (optimized leaf handlers have no prologue). The pointer reference
        // stands in for the prologue signal, with recoverFunctionStarts' same conservatism.
        let dataPointerStartSet = recoverDataPointerStarts(
            candidates: loaded.codePointerTargets,
            rows: decodedInstructions,
            codeStart: codeStart,
            codeEnd: codeEnd,
            existingStarts: startSet,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses,
            noReturnTargets: noReturnTargets
        )
        startSet.formUnion(dataPointerStartSet)
        let trampolineTargetSet = recoverTrampolineTargets(
            rows: decodedInstructions,
            knownStarts: startSet,
            codeStart: codeStart,
            codeEnd: codeEnd,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses,
            noReturnTargets: noReturnTargets
        )
        startSet.formUnion(trampolineTargetSet)
        startSet.subtract(dataAddresses)
        startSet = Self.droppingImportStubSectionStart(
            from: startSet, codeStart: codeStart, codeSectionName: codeSection?.name,
            procedureAddresses: procedureAddresses
        )
        // MS-20: a row the decoder could not decode (`unavailable`, e.g. truncated arm64 text
        // with no complete instruction word) is degraded listing output, never a procedure
        // entry, even when LC_FUNCTION_STARTS or the entry point names its address.
        let undecodedAddresses: Set<UInt64>
        do {
            let span = attribution?.open(.discoveryPrepare, ordinal: discoveryOrdinal)
            defer { attribution?.close(span, outcome: .success) }
            if let cached = preparation.unavailable(sectionOrdinal: sectionOrdinal,
                rows: decodedInstructions) {
                undecodedAddresses = cached
                work?.begin(.preparationFallbackUnavailableBuilds)
            } else {
                work?.add(.preparationFallbackUnavailableBuilds)
                undecodedAddresses = Set(decodedInstructions.lazy.filter { $0.mnemonic == "unavailable" }.map(\.address))
            }
        }
        let starts = startSet.filter {
            decodedInstructionAddresses.contains($0) && !undecodedAddresses.contains($0)
        }.sorted()

        let functionStartSet = Set(functionStartEntries)
        let directCallTargetSet = Set(directCallTargets)
        let recoveredStartSet = recoveredStarts
            .union(dataPointerStartSet)
            .union(trampolineTargetSet)
        work?.add(.sectionCallsCompleted)
        return starts.enumerated().map { index, start in
            // `starts` is sorted ascending, so the next boundary is the adjacent
            // element — O(1) instead of an O(n) `dropFirst().first` per function.
            let nextStart = index + 1 < starts.count ? starts[index + 1] : nil
            let end = nextStart ?? codeEnd ?? start
            return FunctionSummary(
                // HOP-4: identity is (image slot, start address), stable across re-analysis.
                // The engine is image-local; the store re-derives on a slot re-stamp.
                id: AnalysisStableIdentity.functionID(slot: .primary, startAddress: start),
                name: functionName(
                    for: start,
                    entryPoint: loaded.entryPointAddress,
                    codeStart: codeStart,
                    symbolNameByAddress: symbolNameByAddress
                ),
                startAddress: start,
                endAddress: max(start, end),
                confidence: functionConfidence(
                    for: start,
                    entryPoint: loaded.entryPointAddress,
                    hasFunctionStarts: !loaded.functionStarts.isEmpty,
                    functionStartSet: functionStartSet,
                    symbolStartSet: symbolStartSet,
                    directCallTargetSet: directCallTargetSet,
                    recoveredStartSet: recoveredStartSet
                )
            )
        }
    }

    private func directCallFunctionStarts(
        from instructions: ArraySlice<DecodedInstruction>,
        codeStart: UInt64?,
        codeEnd: UInt64?,
        existingStarts: Set<UInt64>
    ) -> Set<UInt64> {
        let decodedInstructionAddresses = Set(instructions.map(\.address))
        return DiscoveryPreparationStore.directCalls(rows: instructions,
            addresses: decodedInstructionAddresses, codeStart: codeStart,
            codeEnd: codeEnd, existingStarts: existingStarts)
    }

    /// Recursive-descent / worklist recovery of function starts the linear
    /// LC_FUNCTION_STARTS pass omitted. The slicer in `makeFunctionSummaries` partitions
    /// text into `[start, nextStart)` ranges, so a SINGLE missed start silently merges
    /// two adjacent functions and corrupts every downstream CFG/decompile/xref. This pass
    /// recovers the boundary — but a FALSE SPLIT (cutting one real function in two, so a
    /// CFG edge crosses a bogus boundary and the decompile/xref are wrong) is just as
    /// corrupting, so promotion is strictly conservative. An address is recovered ONLY when:
    ///
    ///  - it begins a standard arm64 prologue (`stp x29, x30, [sp...]` or `sub sp, sp, #imm`); AND
    ///  - it is immediately preceded (in address order) by a function terminator
    ///    (`ret` / unconditional branch / indirect tail-call); AND
    ///  - it is NOT the target of any direct branch (conditional or unconditional jump).
    ///
    /// The branch-target exclusion is the key guard: a prologue-shaped instruction reached
    /// by a branch is a landing pad / stack re-adjust block / loop header (the
    /// `…ret / L: sub sp` early-return idiom, or a `b` into a mid-function stack setup) —
    /// distinguishing those from a genuine tail-called function needs full CFG analysis we
    /// don't do here, so we never split on a branch target. That can only cost a recoverable
    /// false MERGE of a tail-called function, never corrupt a real one. What survives is the
    /// valuable, safe case: a function reached only by a CALL (already seeded), an indirect/
    /// pointer reference, or laid out after a terminator — exactly the starts the linear
    /// pass misses. Data-marked addresses are filtered downstream by `dataAddresses`.
    private func recoverFunctionStarts(
        from instructions: ArraySlice<DecodedInstruction>,
        codeStart: UInt64?,
        codeEnd: UInt64?,
        existingStarts: Set<UInt64>,
        noReturnTargets: Set<UInt64> = []
    ) -> Set<UInt64> {
        guard !instructions.isEmpty else { return [] }

        // Address order is the boundary order; retain the defensive sort for ties
        // or out-of-order rows rather than assume the decoder's order.
        let sorted = addressOrderedRows(instructions)
        let prologueAddresses = Set(sorted.filter { isPrologueStart($0) }.map(\.address))
        // The filter evaluates the predicate once per ordered row.
        work?.add(.prologueRowsVisited, sorted.count)
        guard !prologueAddresses.isEmpty else { return [] }

        // Targets of direct branches (conditional + unconditional jumps — NOT calls): a
        // prologue reached by one is intra/inter-function control flow we must not split on.
        // Call (`bl`) targets are real function starts and are seeded elsewhere, so they're
        // intentionally excluded from this exclusion set.
        let branchTargets = Set(sorted.compactMap { instruction -> UInt64? in
            switch instruction.flow {
            case .conditionalJump, .jump: return instruction.branchTarget
            default: return nil
            }
        })

        if let work {
            work.add(.branchTargetBuilds)
            work.add(.branchTargetRowsVisited, sorted.count)
        }

        var recovered = Set<UInt64>()
        var candidateVisits = 0, terminatorTests = 0
        for index in sorted.indices where index > sorted.startIndex {
            candidateVisits += 1
            let candidate = sorted[index]
            guard prologueAddresses.contains(candidate.address) else { continue }
            guard !existingStarts.contains(candidate.address) else { continue }
            guard !branchTargets.contains(candidate.address) else { continue }
            guard isAddressInExecutableText(candidate.address, codeStart: codeStart, codeEnd: codeEnd) else { continue }
            terminatorTests += 1
            if isFunctionTerminator(sorted[index - 1], noReturnTargets: noReturnTargets) {
                recovered.insert(candidate.address)
            }
        }
        if let work {
            work.add(.recoveryCandidateRowsVisited, candidateVisits)
            work.add(.recoveryTerminatorTests, terminatorTests)
        }

        return recovered
    }

    /// Recovers function starts referenced only by a data code-pointer (function-pointer tables,
    /// vtables, dispatch tables). The pointer reference stands in for the prologue signal of
    /// `recoverFunctionStarts` — so prologue-less optimized leaf handlers are found — but the SAME
    /// conservatism guards apply: the candidate must be a decoded, in-text, non-data-marked
    /// instruction start; must be immediately preceded (address order) by a function terminator
    /// (or be the code-section start); and must NOT be the target of a direct branch. Those keep a
    /// mid-function pointer (an absolute jump-table entry / computed-goto label) from splitting a
    /// real function. A padded start (padding between the prior `ret` and the target) fails the
    /// terminator check and is left merged — a recoverable false MERGE, never a corrupting split.
    /// `internal` (not `private`) so the conservatism guards are unit-tested directly; the
    /// loader→engine fixup wiring is covered by the real-binary dispatch-table oracle.
    func recoverDataPointerStarts(
        candidates: [UInt64],
        from instructions: [DecodedInstruction],
        codeStart: UInt64?,
        codeEnd: UInt64?,
        existingStarts: Set<UInt64>,
        decodedInstructionAddresses: Set<UInt64>,
        dataAddresses: Set<UInt64>,
        noReturnTargets: Set<UInt64> = []
    ) -> Set<UInt64> {
        recoverDataPointerStarts(candidates: candidates, rows: instructions[...],
            codeStart: codeStart, codeEnd: codeEnd, existingStarts: existingStarts,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses, noReturnTargets: noReturnTargets)
    }

    func recoverDataPointerStarts(
        candidates: [UInt64], rows instructions: ArraySlice<DecodedInstruction>,
        codeStart: UInt64?, codeEnd: UInt64?, existingStarts: Set<UInt64>,
        decodedInstructionAddresses: Set<UInt64>, dataAddresses: Set<UInt64>,
        noReturnTargets: Set<UInt64> = []
    ) -> Set<UInt64> {
        let candidateSet = Set(candidates).subtracting(existingStarts)
        work?.add(.dataPointerCandidateSetBuilds)
        guard !candidateSet.isEmpty, !instructions.isEmpty else { return [] }
        let sorted = addressOrderedRows(instructions)
        // Addresses that immediately follow a function terminator — the boundary signal.
        var afterTerminator = Set<UInt64>()
        for index in sorted.indices where index > sorted.startIndex
            && isFunctionTerminator(sorted[index - 1], noReturnTargets: noReturnTargets) {
            afterTerminator.insert(sorted[index].address)
        }
        if let work {
            work.add(.afterTerminatorBuilds)
            // The where clause tests the predecessor of every row after the first.
            work.add(.afterTerminatorRowsVisited, Swift.max(0, sorted.count - 1))
        }
        // Direct-branch (conditional + unconditional jump, NOT call) targets: a candidate reached
        // by one is intra-function control flow, never split on it (mirrors recoverFunctionStarts).
        let branchTargets = Set(sorted.compactMap { instruction -> UInt64? in
            switch instruction.flow {
            case .conditionalJump, .jump: return instruction.branchTarget
            default: return nil
            }
        })
        if let work {
            work.add(.dataPointerBranchTargetBuilds)
            work.add(.dataPointerBranchTargetRowsVisited, sorted.count)
            // The filter enters its predicate once per candidate.
            work.add(.dataPointerCandidatesVisited, candidateSet.count)
        }
        return candidateSet.filter { address in
            guard decodedInstructionAddresses.contains(address) else { return false }
            guard isAddressInExecutableText(address, codeStart: codeStart, codeEnd: codeEnd) else { return false }
            guard !dataAddresses.contains(address) else { return false }
            guard !branchTargets.contains(address) else { return false }
            return afterTerminator.contains(address) || address == codeStart
        }
    }

    /// Recovers tail-call trampoline targets. A known function start whose body begins with an
    /// unconditional direct branch is a thunk, so its target may be a real function entry reached
    /// only through that trampoline. Promotion still uses the strict boundary guard: decoded,
    /// in executable text, not data-marked, and immediately after a function terminator or codeStart.
    func recoverTrampolineTargets(
        from instructions: [DecodedInstruction],
        knownStarts: Set<UInt64>,
        codeStart: UInt64?,
        codeEnd: UInt64?,
        decodedInstructionAddresses: Set<UInt64>,
        dataAddresses: Set<UInt64>,
        noReturnTargets: Set<UInt64> = []
    ) -> Set<UInt64> {
        recoverTrampolineTargets(rows: instructions[...], knownStarts: knownStarts,
            codeStart: codeStart, codeEnd: codeEnd,
            decodedInstructionAddresses: decodedInstructionAddresses,
            dataAddresses: dataAddresses, noReturnTargets: noReturnTargets)
    }

    func recoverTrampolineTargets(
        rows instructions: ArraySlice<DecodedInstruction>, knownStarts: Set<UInt64>,
        codeStart: UInt64?, codeEnd: UInt64?,
        decodedInstructionAddresses: Set<UInt64>, dataAddresses: Set<UInt64>,
        noReturnTargets: Set<UInt64> = []
    ) -> Set<UInt64> {
        guard !instructions.isEmpty, !knownStarts.isEmpty else { return [] }

        let sorted = addressOrderedRows(instructions)
        var instructionByAddress: [UInt64: DecodedInstruction] = [:]
        for instruction in sorted where instructionByAddress[instruction.address] == nil {
            instructionByAddress[instruction.address] = instruction
        }
        if let work {
            work.add(.trampolineRowsVisited, sorted.count)
            work.add(.trampolineIndexBuilds)
        }

        var afterTerminator = Set<UInt64>()
        for index in sorted.indices where index > sorted.startIndex
            && isFunctionTerminator(sorted[index - 1], noReturnTargets: noReturnTargets) {
            afterTerminator.insert(sorted[index].address)
        }
        if let work {
            work.add(.trampolineAfterTerminatorBuilds)
            work.add(.trampolineAfterTerminatorRowsVisited, Swift.max(0, sorted.count - 1))
        }

        var recovered = Set<UInt64>()
        var startVisits = 0
        defer { work?.add(.trampolineStartsVisited, startVisits) }
        for start in knownStarts {
            startVisits += 1
            guard let instruction = instructionByAddress[start] else { continue }
            guard instruction.flow == .jump, let target = instruction.branchTarget else { continue }
            guard !knownStarts.contains(target) else { continue }
            guard decodedInstructionAddresses.contains(target) else { continue }
            guard isAddressInExecutableText(target, codeStart: codeStart, codeEnd: codeEnd) else { continue }
            guard !dataAddresses.contains(target) else { continue }
            guard afterTerminator.contains(target) || target == codeStart else { continue }
            recovered.insert(target)
        }

        return recovered
    }

    /// A standard arm64 function prologue: the frame-record store
    /// `stp x29, x30, [sp...]` or a stack-allocating `sub sp, sp, #imm`. Matched against
    /// the decoder's exact operand spelling (see ARM64Decoder) so a non-prologue `stp`
    /// (e.g. `stp x0, x1, ...`) or a non-stack `sub` is never mistaken for a frame setup.
    private func isPrologueStart(_ instruction: DecodedInstruction) -> Bool {
        let operands = instruction.operands
        switch instruction.mnemonic {
        case "stp":
            // Frame-record save: the link register x30 paired with the frame pointer x29
            // into the stack. Tolerate both `[sp]`, `[sp, #..]` and the pre-index `]!`.
            return operands.hasPrefix("x29, x30, [sp")
        case "sub":
            // Stack allocation `sub sp, sp, #imm` — the canonical frameless prologue.
            return operands.hasPrefix("sp, sp, #")
        default:
            return false
        }
    }

    /// An instruction that ends a function's linear extent: a return, an unconditional
    /// direct branch (tail call to a sibling), or an indirect branch (tail call / switch
    /// dispatch). A conditional branch is NOT a terminator — its fall-through keeps the
    /// function going — so a prologue after a `b.eq` is correctly left un-split.
    private func isFunctionTerminator(
        _ instruction: DecodedInstruction,
        noReturnTargets: Set<UInt64> = []
    ) -> Bool {
        // HOP-1: a call to a known no-return target ends the function like a trap.
        if NoReturnAnalysis.isNoReturnCall(instruction, targets: noReturnTargets) { return true }
        switch instruction.flow {
        case .return, .jump, .indirectJump, .trap:
            return true
        case .normal, .call, .indirectCall, .conditionalJump:
            return false
        }
    }

    private func isAddressInExecutableText(
        _ address: UInt64,
        codeStart: UInt64?,
        codeEnd: UInt64?
    ) -> Bool {
        guard let codeStart, let codeEnd else { return true }
        return address >= codeStart && address < codeEnd
    }

    static func isImportStubSection(named name: String) -> Bool {
        StubCallSymbolicator.linkageSlotClass(sectionName: name) == .executableImportStub
    }

    /// Apply after all automatic recovery so data pointers and trampolines cannot
    /// re-seed an import-stub section start. A user-forced procedure remains eligible.
    static func droppingImportStubSectionStart(
        from starts: Set<UInt64>,
        codeStart: UInt64?,
        codeSectionName: String?,
        procedureAddresses: Set<UInt64>
    ) -> Set<UInt64> {
        guard let codeStart, let codeSectionName,
              isImportStubSection(named: codeSectionName),
              !procedureAddresses.contains(codeStart) else { return starts }
        return starts.subtracting([codeStart])
    }

    private func functionName(
        for address: UInt64,
        entryPoint: UInt64?,
        codeStart: UInt64?,
        symbolNameByAddress: [UInt64: String]
    ) -> String {
        if let symbol = symbolNameByAddress[address] {
            return symbol
        }
        if entryPoint == address {
            return "_entry"
        }
        if entryPoint == nil, codeStart == address {
            return "__text"
        }
        return "sub_\(address.hexAddress)"
    }

    private func functionConfidence(
        for address: UInt64,
        entryPoint: UInt64?,
        hasFunctionStarts: Bool,
        functionStartSet: Set<UInt64>,
        symbolStartSet: Set<UInt64>,
        directCallTargetSet: Set<UInt64>,
        recoveredStartSet: Set<UInt64> = []
    ) -> Double {
        if functionStartSet.contains(address) {
            return 0.74
        }
        if entryPoint == address {
            return hasFunctionStarts ? 0.72 : 0.7
        }
        if symbolStartSet.contains(address) {
            return 0.66
        }
        if directCallTargetSet.contains(address) {
            return 0.62
        }
        // A start recovered from a prologue at a true inter-function boundary is a
        // strong but not authoritative signal — it ranks above a bare linear-sweep
        // fallback yet below a direct-call target, which has explicit caller evidence.
        if recoveredStartSet.contains(address) {
            return 0.6
        }
        return entryPoint == nil ? 0.45 : 0.58
    }

    /// Disk Mach-O symbol candidates only. Format-neutral kind strings from other
    /// loaders do not establish this admission policy.
    private func symbolFunctionStartCandidates(in loaded: LoadedBinary) -> Set<UInt64> {
        guard !loaded.isDyldSharedCacheProjection,
              !loaded.fileTypeName.hasPrefix("ELF"),
              !loaded.fileTypeName.hasPrefix("PE "),
              !loaded.fileTypeName.hasPrefix("COFF") else { return [] }
        return Set(loaded.symbols.compactMap { symbol in
            guard symbol.kind == "local" || symbol.kind == "export",
                  !symbol.name.hasPrefix("ltmp"), !symbol.name.hasPrefix("L") else { return nil }
            return symbol.address
        })
    }

    /// One section-derived, alias-safe authority for patch admission, code and
    /// table reads. No read may project a section over a neighboring file span.
    private func makeByteMappings(loaded: LoadedBinary) -> [FileAddressMapping] {
        let sections = loaded.sections.map {
            SectionSummary(id: UUID(), name: $0.name, address: $0.address, size: $0.size,
                           fileOffset: $0.fileOffset, isExecutable: $0.isExecutable,
                           isZeroFill: $0.isZeroFill, fileSize: $0.fileSize, coffCoordinate: $0.coffCoordinate)
        }
        return FileAddressMapping.verifiedMappings(
            from: sections, payloadLength: exactSliceRange(of: loaded)?.count ?? 0
        )
    }

    private static func mappedBytes(
        in loaded: LoadedBinary, at address: UInt64, count: Int, mappings: [FileAddressMapping]
    ) -> Data? {
        RehydrationDerivedProducts.mappedBytes(in: loaded.bytes, sliceOffset: loaded.sliceOffset,
            at: address, count: count, mappings: mappings)
    }

    private func decodeInstructions(
        from loaded: LoadedBinary, decoder: any Disassembler,
        patchOverlay: BytePatchOverlay, byteMappings: [FileAddressMapping]
    ) -> [DecodedInstruction] {
        let sections = executableCodeSections(in: loaded, mappings: byteMappings)
        if let work {
            work.add(.codeSectionBuilds)
            work.add(.decodeCodeSectionRows, sections.count)
        }
        guard !sections.isEmpty else {
            return [
                DecodedInstruction(
                    address: loaded.entryPointAddress ?? 0,
                    bytes: [],
                    mnemonic: "unavailable",
                    operands: "",
                    branchTarget: nil,
                    comment: "No executable text section was found"
                )
            ]
        }

        var result: [DecodedInstruction] = []
        for codeSection in sections {
        guard let decodeCount = Int(exactly: codeSection.size), decodeCount > 0,
              let rawBytes = Self.mappedBytes(
                in: loaded, at: codeSection.address, count: decodeCount, mappings: byteMappings
              ),
              let codeBytes = patchOverlay.applying(to: rawBytes, at: codeSection.address) else {
            continue
        }
        // Decode the entire executable text section rather than the historical
        // first-1024-bytes window. The ceiling is the BYTE count (not word count):
        // arm64 self-caps at one instruction per 4 bytes, while x86_64 is
        // variable-length and can pack up to one instruction per byte, so a /4
        // ceiling would truncate x86 coverage. Each decoder stops at the real end
        // of the byte range regardless; downstream passes are linear in count.
        let decoded = decoder.decode(
            codeBytes,
            baseAddress: codeSection.address,
            maxInstructionCount: decodeCount
        )
        result += decoded.map { instruction in
            guard patchOverlay.intersects(address: instruction.address, count: instruction.bytes.count)
            else { return instruction }
            var row = instruction
            row.comment = row.comment.map { "\($0) ; patched" } ?? "patched"
            return row
        }
        }
        return result
    }

    /// Loader-declared code sections, clipped to their physically mapped prefixes.
    /// Never widen disjoint intervals to a min/max envelope or decode an alias.
    private func executableCodeSections(in loaded: LoadedBinary, mappings: [FileAddressMapping]) -> [BinarySection] {
        let sections = loaded.sections.map {
            SectionSummary(id: UUID(), name: $0.name, address: $0.address, size: $0.size,
                fileOffset: $0.fileOffset, isExecutable: $0.isExecutable,
                isZeroFill: $0.isZeroFill, fileSize: $0.fileSize, coffCoordinate: $0.coffCoordinate)
        }
        return RehydrationDerivedProducts.executableCodeSections(sections: sections,
            layout: loaded.preferredSegmentLayout, mappings: mappings).map {
                BinarySection(name: $0.name, address: $0.address, size: $0.size,
                    fileOffset: $0.fileOffset, isExecutable: $0.isExecutable,
                    isZeroFill: $0.isZeroFill, fileSize: $0.fileSize, coffCoordinate: $0.coffCoordinate)
            }
    }

    private static func addressIndex<Element>(_ value: UInt64, in rows: [Element],
                                               address: KeyPath<Element, UInt64>) -> Int {
        var lower = 0
        var upper = rows.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            if rows[middle][keyPath: address] < value { lower = middle + 1 } else { upper = middle }
        }
        return lower
    }

    /// Strict order makes sorting an identity; ties take the original sort.
    /// Returned slices are local views, never retained by discovery preparation.
    private func addressOrderedRows(_ rows: ArraySlice<DecodedInstruction>) -> ArraySlice<DecodedInstruction> {
        var previous: UInt64?
        var visited = 0
        for row in rows {
            visited += 1
            if let previous, row.address <= previous {
                attribution?.add(.sortsRun, 1)
                if let work {
                    work.add(.orderedRowRequests)
                    work.add(.orderedRowBuilds)
                    work.add(.orderedRowsVisited, visited)
                }
                return rows.sorted { $0.address < $1.address }[...]
            }
            previous = row.address
        }
        attribution?.add(.sortsSkipped, 1)
        if let work {
            work.add(.orderedRowRequests)
            work.begin(.orderedRowBuilds)
            work.add(.orderedRowsVisited, visited)
        }
        return rows
    }

    /// Validates that the loader's declared selected-slice extent fits inside the container.
    /// A slice offset past the end, or `offset + size` beyond the container, is REFUSED rather
    /// than silently clamped — a malformed fat entry must never yield a truncated/over-reaching
    /// persisted payload. A nil `sliceSize` (thin binary: run to EOF) only needs a valid offset.
    private func validateSelectedSliceRange(of loaded: LoadedBinary) throws {
        let containerSize = loaded.bytes.count
        guard loaded.sliceOffset <= UInt64(containerSize) else {
            throw AnalysisEngineError.invalidSelectedSliceRange(
                offset: loaded.sliceOffset, size: loaded.sliceSize, containerSize: containerSize
            )
        }
        guard let size = loaded.sliceSize else { return }
        let available = UInt64(containerSize) - loaded.sliceOffset
        guard size <= available else {
            throw AnalysisEngineError.invalidSelectedSliceRange(
                offset: loaded.sliceOffset, size: size, containerSize: containerSize
            )
        }
    }

    /// The exact selected-slice payload: `bytes[sliceOffset ..< sliceOffset + sliceSize]`, or
    /// `bytes[sliceOffset ..< end]` for a thin binary (nil `sliceSize`). `validateSelectedSliceRange`
    /// has already proven this range fits, so the bounds here are belt-and-suspenders.
    func exactSliceRange(of loaded: LoadedBinary) -> Range<Int>? {
        guard let start = selectedSliceFileOffset(relativeOffset: 0, sliceOffset: loaded.sliceOffset),
              start >= 0, start <= loaded.bytes.count else { return nil }
        let end: Int
        if let size = loaded.sliceSize, size <= UInt64(loaded.bytes.count - start) {
            end = start + Int(size)
        } else {
            end = loaded.bytes.count
        }
        guard end >= start else { return nil }
        return start..<end
    }

    private func selectedSliceBytes(from loaded: LoadedBinary) -> Data {
        // The bounded hex-VIEW window only — a bounded PREFIX of the exact selected slice. The
        // full persisted bytes come from `sliceBytes` (-> snapshot.imageBytes); this must never
        // be treated as the source of truth.
        let window = WorkspaceSnapshot.hexViewByteWindow
        guard let range = exactSliceRange(of: loaded) else {
            return Data(loaded.bytes.prefix(window))
        }
        let byteCount = min(window, range.count)
        return loaded.bytes.subdata(in: range.lowerBound..<(range.lowerBound + byteCount))
    }

    /// The selected slice's EXACT bytes (offset to declared slice end, NOT end of file), the
    /// backing store for `read-bytes`. Section `fileOffset`s are slice-relative, so they index
    /// directly into this. Returns empty when the slice offset can't be resolved.
    func sliceBytes(from loaded: LoadedBinary) -> Data {
        guard let range = exactSliceRange(of: loaded) else { return Data() }
        return loaded.bytes.subdata(in: range)
    }

    private func selectedSliceFileOffset(relativeOffset: UInt64, sliceOffset: UInt64) -> Int? {
        guard sliceOffset <= UInt64(Int.max) else { return nil }
        guard relativeOffset <= UInt64(Int.max) else { return nil }
        guard sliceOffset <= UInt64(Int.max) - relativeOffset else { return nil }
        return Int(sliceOffset + relativeOffset)
    }

    // Internal (not private) so the CFG construction is directly unit-testable.
    func buildBasicBlocks(
        from instructions: [DecodedInstruction],
        functions: [FunctionSummary],
        codeStart: UInt64?,
        jumpTables: [UInt64: [UInt64]] = [:],
        noReturnTargets: Set<UInt64> = []
    ) -> [BasicBlockSummary] {
        guard !instructions.isEmpty, !functions.isEmpty else { return [] }
        work?.begin(.blocks)

        // `instructions` arrive in strictly ascending, unique address order (the
        // decoder emits contiguous 4-byte words). Every pass below relies on that
        // invariant to stay linear when the whole text section is decoded.
        let instructionAddresses = Set(instructions.map(\.address))
        let firstAddress = codeStart ?? instructions[0].address
        var blockStarts: Set<UInt64> = Set(functions.map(\.startAddress))
        blockStarts.formUnion(functions.map(\.endAddress).filter { instructionAddresses.contains($0) })
        blockStarts.insert(firstAddress)
        // Switch-case targets of a `br` jump-table dispatch begin blocks too — the
        // indirect branch has no static `branchTarget`, so without this they'd be
        // mid-block. Only in-text decoded targets count (no phantom leaders).
        for targets in jumpTables.values {
            for target in targets where instructionAddresses.contains(target) {
                blockStarts.insert(target)
            }
        }

        for (index, instruction) in instructions.enumerated() {
            if let target = instruction.branchTarget, instructionAddresses.contains(target) {
                blockStarts.insert(target)
            }

            // The fall-through after a terminator begins a new block. The next
            // address is the adjacent (sorted) instruction — O(1) instead of an
            // O(n) scan, which would otherwise make this loop O(n^2).
            if isBlockTerminator(instruction)
                || NoReturnAnalysis.isNoReturnCall(instruction, targets: noReturnTargets),
               index + 1 < instructions.count {
                blockStarts.insert(instructions[index + 1].address)
            }
            // A row that does not physically follow its predecessor (data-in-code, a
            // Mark-as-Data range, an undecodable gap) starts a block: one block never spans
            // bytes that were removed from the instruction stream.
            if index + 1 < instructions.count,
               !Self.isPhysicallyAdjacent(instruction, instructions[index + 1].address) {
                blockStarts.insert(instructions[index + 1].address)
            }
        }

        work?.add(.leaderRowsVisited, instructions.count)
        let sortedStarts = blockStarts.sorted()
        work?.add(.leaders, sortedStarts.count)
        // Functions sorted by start address let `owningFunctionID` binary-search
        // instead of scanning every function per block.
        let sortedFunctions = functions.sorted { $0.startAddress < $1.startAddress }
        let functionsByID = Dictionary(grouping: functions, by: \.id)
        var previousMaximumEnds: [UInt64] = []
        var maximumEnd: UInt64 = 0
        for function in sortedFunctions {
            previousMaximumEnds.append(maximumEnd)
            maximumEnd = max(maximumEnd, function.endAddress)
        }

        // Single merge-walk: each [start, nextStart) range is a contiguous,
        // non-overlapping slice of the sorted instruction stream, so one cursor
        // partitions all instructions into blocks in O(n + starts).
        var blocks: [BasicBlockSummary] = []
        blocks.reserveCapacity(sortedStarts.count)
        let instructionCount = instructions.count
        var cursor = 0
        var ownerQueryCount = 0, extentRows = 0
        for (index, start) in sortedStarts.enumerated() {
            let upperBound = index + 1 < sortedStarts.count ? sortedStarts[index + 1] : UInt64.max
            while cursor < instructionCount, instructions[cursor].address < start {
                cursor += 1
            }
            guard cursor < instructionCount, instructions[cursor].address < upperBound else { continue }

            let first = instructions[cursor]
            ownerQueryCount += 1
            guard let owner = owningFunctionID(for: first.address, functions: sortedFunctions,
                                              previousMaximumEnds: previousMaximumEnds),
                  functionsByID[owner]?.count == 1,
                  let function = functionsByID[owner]?.first else {
                cursor += 1
                continue
            }
            var last = first
            var count = 0
            var scan = cursor
            while scan < instructionCount, instructions[scan].address < min(upperBound, function.endAddress) {
                extentRows += 1
                let candidate = instructions[scan]
                let extent = candidate.address.addingReportingOverflow(UInt64(candidate.bytes.count))
                guard !candidate.bytes.isEmpty, !extent.overflow, extent.partialValue <= function.endAddress else { break }
                last = instructions[scan]
                count += 1
                scan += 1
            }
            guard count > 0 else { cursor += 1; continue }
            blocks.append(BasicBlockSummary(
                id: UUID(),
                functionID: owner,
                startAddress: first.address,
                endAddress: last.address + UInt64(last.bytes.count),
                instructionCount: count
            ))
            cursor = scan
        }
        if let work {
            work.add(.ownerQueries, ownerQueryCount)
            work.add(.blockRowsVisited, extentRows)
            work.add(.blocks, blocks.count)
        }
        return blocks
    }

    func buildControlFlowEdges(
        from instructions: [DecodedInstruction],
        basicBlocks: [BasicBlockSummary],
        jumpTables: [UInt64: [UInt64]] = [:],
        noReturnTargets: Set<UInt64> = []
    ) -> [ControlFlowEdge] {
        guard !instructions.isEmpty else { return [] }
        work?.begin(.emittedEdges)

        var edges: [ControlFlowEdge] = []
        let blockByStart = Dictionary(uniqueKeysWithValues: basicBlocks.map { ($0.startAddress, $0) })
        var currentBlock: BasicBlockSummary?

        for (index, instruction) in instructions.enumerated() {
            if let block = blockByStart[instruction.address] { currentBlock = block }
            if let block = currentBlock, instruction.address >= block.endAddress { currentBlock = nil }
            if let target = instruction.branchTarget {
                edges.append(ControlFlowEdge(
                    id: UUID(),
                    from: instruction.address,
                    to: target,
                    kind: instruction.flow == .call ? "call" : "branch"
                ))
            }

            // A `br` switch dispatch (indirect jump with a resolved jump table) has no
            // static `branchTarget`, so emit a `switch` successor edge to each in-text
            // case target. De-duplicated: a table repeats a target for several cases.
            if let targets = jumpTables[instruction.address] {
                var seen = Set<UInt64>()
                for target in targets where currentBlock != nil
                    && blockByStart[target]?.functionID == currentBlock?.functionID && seen.insert(target).inserted {
                    edges.append(ControlFlowEdge(id: UUID(), from: instruction.address, to: target, kind: "switch"))
                }
            }

            // Fall-through edge to the adjacent (sorted) instruction — O(1). Emitted after a
            // conditional branch, AND when a block ends only because its successor is a leader
            // (a branch target such as a loop header or merge point): control still flows into
            // that block unless this instruction is an unconditional terminator. The implicit
            // case stays within one function so a function's last instruction never links to
            // the next function's entry.
            let next = index + 1 < instructions.count ? instructions[index + 1].address : nil
            // Fall-through needs the next row to start exactly where this instruction's bytes
            // end; the sorted successor can lie across a data or undecoded gap.
            guard let next, let nextBlock = blockByStart[next],
                  let currentBlock, currentBlock.functionID == nextBlock.functionID,
                  Self.isPhysicallyAdjacent(instruction, next) else { continue }
            // HOP-1: no fall-through edge after a call to a known no-return target.
            let implicitFallthrough = !isTerminator(instruction)
                && !NoReturnAnalysis.isNoReturnCall(instruction, targets: noReturnTargets)
            guard isConditionalBranch(instruction) || implicitFallthrough else { continue }
            edges.append(ControlFlowEdge(id: UUID(), from: instruction.address, to: next, kind: "fallthrough"))
        }

        if let work {
            work.add(.edgeRowsVisited, instructions.count)
            work.add(.emittedEdges, edges.count)
        }
        return edges
    }

    /// True only when known bytes end exactly at `next`. Placeholder rows do not
    /// establish executable adjacency.
    static func isPhysicallyAdjacent(_ instruction: DecodedInstruction, _ next: UInt64) -> Bool {
        guard !instruction.bytes.isEmpty else { return false }
        let (end, overflow) = instruction.address.addingReportingOverflow(UInt64(instruction.bytes.count))
        return !overflow && end == next
    }

    private func isBlockTerminator(_ instruction: DecodedInstruction) -> Bool {
        isTerminator(instruction) || instruction.flow == .conditionalJump
    }

    private func isTerminator(_ instruction: DecodedInstruction) -> Bool {
        switch instruction.flow {
        case .return, .jump, .indirectJump, .trap: return true
        default: return false
        }
    }

    private func isConditionalBranch(_ instruction: DecodedInstruction) -> Bool {
        instruction.flow == .conditionalJump
    }

    /// Finds the rightmost function starting at or before `address` by binary search.
    /// `sortedFunctions` is ordered by start address, and `previousMaximumEnds`
    /// holds the largest end among earlier functions, or zero when there are none.
    /// Return an owner only if the candidate contains the address and no earlier
    /// range also contains it; gaps and ambiguous overlaps return nil. If the
    /// rightmost candidate fails, earlier candidates are not searched.
    private func owningFunctionID(for address: UInt64, functions sortedFunctions: [FunctionSummary],
                                  previousMaximumEnds: [UInt64]) -> UUID? {
        var low = 0
        var high = sortedFunctions.count
        while low < high {
            let mid = (low + high) / 2
            if sortedFunctions[mid].startAddress <= address {
                low = mid + 1
            } else {
                high = mid
            }
        }
        let index = low - 1
        guard index >= 0, address < sortedFunctions[index].endAddress,
              previousMaximumEnds[index] <= address else { return nil }
        return sortedFunctions[index].id
    }
}
