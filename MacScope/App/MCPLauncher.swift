import Darwin
import Foundation

enum MCPLauncherError: LocalizedError {
    case binaryIdentityChanged
    case analysisIdentityMismatch
    case unknownSliceArchitecture(requested: String, available: [String])
    case ambiguousSliceArchitecture(requested: String, indices: [Int])
    case sliceRequiresUniversal(requested: String)
    case sliceSelectionMismatch
    case sliceWithWorkspacePackage

    var errorDescription: String? {
        switch self {
        case .binaryIdentityChanged:
            "The canonical binary changed while the headless workspace was active."
        case .analysisIdentityMismatch:
            "The analysis result does not belong to the canonical requested binary."
        case .unknownSliceArchitecture(let requested, let available):
            "No slice named '\(requested)'; available: \(available.joined(separator: ", "))."
        case .ambiguousSliceArchitecture(let requested, let indices):
            "Slice name '\(requested)' matches slices \(indices.map(String.init).joined(separator: ", ")); it is ambiguous."
        case .sliceRequiresUniversal(let requested):
            "--slice \(requested) needs a universal (fat) binary; this file is thin."
        case .sliceSelectionMismatch:
            "The analysis did not select the requested slice."
        case .sliceWithWorkspacePackage:
            "--slice applies to a binary, not a workspace package."
        }
    }
}

/// Headless MCP mode: `MacScope --mcp <binary-path | workspace.mscope>` loads the binary (or
/// opens the saved workspace package, HOP-6) and serves the
/// MCP (JSON-RPC) protocol over stdio instead of presenting the GUI. This is the
/// runnable transport on top of `MCPServer` — an MCP client launches the app with the
/// flag and talks newline-delimited JSON over the process's stdin/stdout.
enum MCPLauncher {
    typealias FileFingerprinter = @Sendable (URL) throws -> WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint

    struct BoundStore {
        let store: WorkspaceStore
        fileprivate let fingerprint: WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint

        func validateIdentity() throws {
            try MCPLauncher.validateBinaryIdentity(fingerprint)
        }

        /// HOP-6: the launch binary is guarded only while the workspace's primary image is still
        /// that binary. After `open-workspace` replaces the workspace with another package's
        /// images, the launch file no longer backs anything this session serves.
        @MainActor
        func validateIdentityWhileBound() throws {
            guard let primary = store.snapshot.binaries.first,
                  URL(fileURLWithPath: primary.path).resolvingSymlinksInPath().standardizedFileURL.path
                    == fingerprint.canonicalPath else { return }
            try validateIdentity()
        }
    }

    /// HOP-6: `--mcp <workspace.mscope>` opens a saved workspace package instead of analyzing a
    /// binary. A package is a directory with the `.mscope` extension.
    static func isWorkspacePackage(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        return url.pathExtension.lowercased() == WorkspaceScriptingAPI.workspacePackageExtension
            && FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }

    /// Parses `--mcp <path>` or `--mcp=<path>` — but ONLY when the flag occupies the
    /// mode slot (the first argument after the program name). Scanning all of argv would
    /// let a positional value from another launch mode (e.g. a `--run-script` path that
    /// happened to start with `--mcp=`) be misread as an MCP selector, silently running
    /// the wrong mode on the wrong file. nil if absent.
    static func requestedBinary(from arguments: [String]) -> URL? {
        guard let flag = arguments.dropFirst().first else { return nil }
        if flag == "--mcp" {
            guard arguments.count == 3 else { return nil }
            return canonicalURL(forPath: arguments[2])
        }
        if flag.hasPrefix("--mcp=") {
            guard arguments.count == 2 else { return nil }
            let path = String(flag.dropFirst("--mcp=".count))
            return canonicalURL(forPath: path)
        }
        return nil
    }

    static func requestedJournalLaunch(from arguments: [String]) -> (binary: URL, journal: URL)? {
        let binaryPath: String
        let journalPath: String
        if arguments.count == 5, arguments[1] == "--mcp", arguments[3] == "--journal" {
            binaryPath = arguments[2]
            journalPath = arguments[4]
        } else if arguments.count == 3, arguments[1].hasPrefix("--mcp="),
                  arguments[2].hasPrefix("--journal=") {
            binaryPath = String(arguments[1].dropFirst("--mcp=".count))
            journalPath = String(arguments[2].dropFirst("--journal=".count))
        } else { return nil }
        guard let binary = canonicalURL(forPath: binaryPath),
              let journal = canonicalURL(forPath: journalPath) else { return nil }
        return (binary, journal)
    }

    static func requestedSliceLaunch(from arguments: [String]) -> (binary: URL, architecture: String)? {
        let path: String
        let architecture: String
        if arguments.count == 5, arguments[1] == "--mcp", arguments[3] == "--slice" {
            path = arguments[2]
            architecture = arguments[4]
        } else if arguments.count == 3, arguments[1].hasPrefix("--mcp="),
                  arguments[2].hasPrefix("--slice=") {
            path = String(arguments[1].dropFirst("--mcp=".count))
            architecture = String(arguments[2].dropFirst("--slice=".count))
        } else { return nil }
        guard !architecture.isEmpty, !architecture.unicodeScalars.contains(where: { $0.value == 0 }),
              let binary = canonicalURL(forPath: path) else { return nil }
        return (binary, architecture)
    }

    /// The combined launch has one fixed order; the existing single-option parsers stay exact.
    static func requestedSliceJournalLaunch(from arguments: [String])
        -> (binary: URL, architecture: String, journal: URL)? {
        let path: String
        let architecture: String
        let journalPath: String
        if arguments.count == 7, arguments[1] == "--mcp", arguments[3] == "--slice",
           arguments[5] == "--journal" {
            path = arguments[2]
            architecture = arguments[4]
            journalPath = arguments[6]
        } else if arguments.count == 4, arguments[1].hasPrefix("--mcp="),
                  arguments[2].hasPrefix("--slice="), arguments[3].hasPrefix("--journal=") {
            path = String(arguments[1].dropFirst("--mcp=".count))
            architecture = String(arguments[2].dropFirst("--slice=".count))
            journalPath = String(arguments[3].dropFirst("--journal=".count))
        } else { return nil }
        guard !architecture.isEmpty, !architecture.unicodeScalars.contains(where: { $0.value == 0 }),
              let binary = canonicalURL(forPath: path),
              let journal = canonicalURL(forPath: journalPath) else { return nil }
        return (binary, architecture, journal)
    }

    static func sliceIndex(forArchitecture architecture: String,
                           in slices: [MachOUniversalSlice]?) throws -> Int {
        guard let slices else { throw MCPLauncherError.sliceRequiresUniversal(requested: architecture) }
        let matches = slices.filter { $0.architectureName == architecture }
        guard !matches.isEmpty else {
            throw MCPLauncherError.unknownSliceArchitecture(requested: architecture,
                                                            available: slices.map(\.architectureName))
        }
        guard matches.count == 1 else {
            throw MCPLauncherError.ambiguousSliceArchitecture(requested: architecture,
                                                              indices: matches.map(\.index))
        }
        return matches[0].index
    }

    private static func requestedSliceSelection(at url: URL, architecture: String?,
                                               attribution: AnalysisAttribution? = nil) throws
        -> (index: Int, slices: [MachOUniversalSlice])? {
        let span = attribution?.open(.selection)
        var outcome = AnalysisAttribution.Outcome.failed
        defer { attribution?.close(span, outcome: outcome) }
        guard let architecture else { outcome = .success; return nil }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let slices = try MachOParser().strictUniversalSlices(in: data)
        let index = try sliceIndex(forArchitecture: architecture, in: slices)
        guard let slices else { throw MCPLauncherError.sliceRequiresUniversal(requested: architecture) }
        outcome = .success
        return (index, slices)
    }

    private static func verifySliceSelection(
        _ selection: (index: Int, slices: [MachOUniversalSlice])?, snapshot: WorkspaceSnapshot,
        attribution: AnalysisAttribution? = nil
    ) throws {
        let span = attribution?.open(.verifySelection)
        var outcome = AnalysisAttribution.Outcome.failed
        defer { attribution?.close(span, outcome: outcome) }
        guard let selection else { outcome = .success; return }
        // The fact records the Mach-O header subtype, which may differ from the fat entry.
        guard let fact = snapshot.binaries.first?.machOSelectedSliceFact,
              fact.containerKind == .universal, fact.sliceCount == selection.slices.count,
              fact.selectedSliceIndex == selection.index,
              let row = selection.slices.first(where: { $0.index == selection.index }),
              fact.cpuType == row.cpuType else { throw MCPLauncherError.sliceSelectionMismatch }
        outcome = .success
    }

    static func canonicalURL(forPath path: String) -> URL? {
        guard !path.isEmpty, !path.unicodeScalars.contains(where: { $0.value == 0 }) else {
            return nil
        }
        let expanded = (path as NSString).expandingTildeInPath
        return URL(fileURLWithPath: expanded)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .standardizedFileURL
    }

    /// Loads the binary into a headless workspace store.
    @MainActor
    static func makeStore(binaryURL: URL, engine: any AnalysisProviding = AnalysisEngine(),
                          sliceArchitecture: String? = nil) throws -> WorkspaceStore {
        try makeBoundStore(binaryURL: binaryURL, engine: engine, sliceArchitecture: sliceArchitecture).store
    }

    /// Binds one canonical regular file identity to the returned store. The whole-file
    /// fingerprint is checked on both sides of analysis so a symlink retarget, replacement,
    /// truncation, or in-place edit cannot silently establish a different workspace.
    @MainActor
    static func makeBoundStore(
        binaryURL: URL,
        engine: any AnalysisProviding = AnalysisEngine(),
        sliceArchitecture: String? = nil
    ) throws -> BoundStore {
        let binding = try beginBinding(binaryURL: binaryURL,
            fingerprint: WorkspaceScriptingAPI.callArgumentAuditFileFingerprint(at:))
        let selection = try requestedSliceSelection(at: binding.canonicalURL, architecture: sliceArchitecture)
        let snapshot = try engine.analyze(
            url: binding.canonicalURL, requestedSliceIndex: selection?.index, overrides: [:], cancellation: .never
        )
        try verifySliceSelection(selection, snapshot: snapshot)
        try verifyLaunchBinding(initial: binding.initial, canonicalURL: binding.canonicalURL,
            snapshot: snapshot, fingerprint: WorkspaceScriptingAPI.callArgumentAuditFileFingerprint(at:))
        return bindLaunchStore(canonicalURL: binding.canonicalURL, snapshot: snapshot,
                               engine: engine, initial: binding.initial)
    }

    private static func beginBinding(binaryURL: URL, fingerprint: FileFingerprinter,
                                     attribution: AnalysisAttribution? = nil) throws
        -> (initial: WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint, canonicalURL: URL) {
        let span = attribution?.open(.initialFingerprint)
        var outcome = AnalysisAttribution.Outcome.failed
        defer { attribution?.close(span, outcome: outcome) }
        let initial = try fingerprint(binaryURL)
        outcome = .success
        return (initial, URL(fileURLWithPath: initial.canonicalPath).standardizedFileURL)
    }

    private static func verifyLaunchBinding(
        initial: WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint,
        canonicalURL: URL, snapshot: WorkspaceSnapshot, fingerprint: FileFingerprinter,
        attribution: AnalysisAttribution? = nil
    ) throws {
        let span = attribution?.open(.finalFingerprint)
        var outcome = AnalysisAttribution.Outcome.failed
        defer { attribution?.close(span, outcome: outcome) }
        let final = try fingerprint(canonicalURL)
        guard final == initial else { throw MCPLauncherError.binaryIdentityChanged }
        guard let primary = snapshot.binaries.first,
              URL(fileURLWithPath: primary.path)
                .resolvingSymlinksInPath().standardizedFileURL.path == canonicalURL.path else {
            throw MCPLauncherError.analysisIdentityMismatch
        }
        outcome = .success
    }

    @MainActor
    private static func bindLaunchStore(
        canonicalURL: URL, snapshot: WorkspaceSnapshot, engine: any AnalysisProviding,
        initial: WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint,
        attribution: AnalysisAttribution? = nil
    ) -> BoundStore {
        let span = attribution?.open(.bind)
        defer { attribution?.close(span, outcome: .success) }
        let store = WorkspaceStore(
            workspaceName: canonicalURL.lastPathComponent,
            snapshot: snapshot,
            engine: engine
        )
        return BoundStore(store: store, fingerprint: initial)
    }

    @MainActor
    static func makeBoundStoreInBackground(
        binaryURL: URL, engine: any AnalysisProviding = AnalysisEngine(), status: MCPStartupStatus,
        fingerprint: @escaping FileFingerprinter = WorkspaceScriptingAPI.callArgumentAuditFileFingerprint(at:),
        onLaunchState: @escaping @Sendable (MCPLaunchState) -> Void = MCPFatalSignalReporter.note,
        sliceArchitecture: String? = nil,
        attribution: AnalysisAttribution? = nil,
        preDispatch: AnalysisAttribution.Span? = nil
    ) async throws -> BoundStore {
        let analysisEngine: any AnalysisProviding
        if let attribution, var concrete = engine as? AnalysisEngine {
            concrete.attribution = attribution
            analysisEngine = concrete
        } else {
            analysisEngine = engine
        }
        let result = try await Task.detached(priority: .userInitiated) {
            // End boundary only: nothing can throw between entry and close.
            attribution?.close(preDispatch, outcome: .success)
            onLaunchState(.fingerprinting)
            MCPFatalSignalReporter.prepareAlternateStack()
            // No suspension from alternate-stack preparation through verification:
            // analyze is synchronous, so all this work stays on the prepared thread.
            let binding = try beginBinding(binaryURL: binaryURL, fingerprint: fingerprint,
                                          attribution: attribution)
            let selection = try requestedSliceSelection(at: binding.canonicalURL,
                architecture: sliceArchitecture, attribution: attribution)
            let snapshot = try analysisEngine.analyze(
                url: binding.canonicalURL, requestedSliceIndex: selection?.index, overrides: [:],
                cancellation: .budgeted(isCancelled: { status.isCancelRequested },
                                        progress: { status.report($0) }))
            onLaunchState(.verifying)
            try verifySliceSelection(selection, snapshot: snapshot, attribution: attribution)
            try verifyLaunchBinding(initial: binding.initial, canonicalURL: binding.canonicalURL,
                                    snapshot: snapshot, fingerprint: fingerprint, attribution: attribution)
            let handoff = attribution?.open(.backgroundHandoff)
            return (binding.initial, binding.canonicalURL, snapshot, handoff)
        }.value
        // End boundary only: the successful await has already completed.
        attribution?.close(result.3, outcome: .success)
        MCPFatalSignalReporter.prepareAlternateStack()
        onLaunchState(.binding)
        return bindLaunchStore(canonicalURL: result.1, snapshot: result.2,
                               engine: engine, initial: result.0, attribution: attribution)
    }

    @MainActor
    static func startHeadlessSession(
        binaryURL: URL, journalURL: URL? = nil, engine: any AnalysisProviding = AnalysisEngine(),
        log: @escaping @Sendable (String) -> Void = MCPStartupLog.line,
        fingerprint: @escaping FileFingerprinter = WorkspaceScriptingAPI.callArgumentAuditFileFingerprint(at:),
        onLaunchState: @escaping @Sendable (MCPLaunchState) -> Void = MCPFatalSignalReporter.note,
        sliceArchitecture: String? = nil,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        attribution: AnalysisAttribution? = nil
    ) -> (server: MCPServer, gate: MCPStartupGate, analysis: Task<Void, Never>) {
        let attribution = attribution ?? AnalysisAttribution.fromEnvironment()
        let status = MCPStartupStatus(onNewPhase: {
            log("phase \($0.rawValue)")
            onLaunchState(.analyzing($0))
        })
        let preDispatch = attribution?.open(.readyPreDispatch)
        let gate = MCPStartupGate(status: status)
        log("analyzing \(binaryURL.path)")
        var timedServer = MCPServer(startup: gate, configuration: MCPToolListingProfile.launchConfiguration())
        timedServer.timing = MCPRequestTiming.selected(environment: environment, observer: MCPRequestTimingRecorder())
        let server = timedServer
        let analysis = Task { @MainActor in
            MCPFatalSignalReporter.prepareAlternateStack()
            do {
                let bound = try await makeBoundStoreInBackground(binaryURL: binaryURL, engine: engine,
                    status: status, fingerprint: fingerprint, onLaunchState: onLaunchState,
                    sliceArchitecture: sliceArchitecture, attribution: attribution, preDispatch: preDispatch)
                MCPFatalSignalReporter.prepareAlternateStack()
                if let journalURL {
                    let span = attribution?.open(.journal)
                    var outcome = AnalysisAttribution.Outcome.failed
                    defer { attribution?.close(span, outcome: outcome) }
                    try attachLaunchJournal(bound.store, journalURL: journalURL, binaryURL: binaryURL, log: log)
                    outcome = .success
                }
                do {
                    let span = attribution?.open(.navigatorSchedule)
                    defer { attribution?.close(span, outcome: .success) }
                    scheduleNavigatorForBinaryLaunch(in: bound.store)
                }
                do {
                    let span = attribution?.open(.apiInstall)
                    defer { attribution?.close(span, outcome: .success) }
                    gate.install(api: WorkspaceScriptingAPI(store: bound.store,
                        nativeDecompiler: NativeDecompilerRuntimeRegistry.productionShared),
                        validateIdentity: { try bound.validateIdentityWhileBound() })
                }
                onLaunchState(.ready)
                log("ready in \(status.snapshot().elapsedMs) ms")
                if let summary = attribution?.summaryWithWork() { log(summary) }
            } catch {
                MCPFatalSignalReporter.prepareAlternateStack()
                onLaunchState(.failed)
                gate.fail(error.localizedDescription)
                let value = status.snapshot()
                log("analysis failed after \(value.elapsedMs) ms (phase \(value.phase?.rawValue ?? "none")): \(error.localizedDescription)")
                if let summary = attribution?.summaryWithWork() { log(summary) }
            }
        }
        return (server, gate, analysis)
    }

    /// Attaches the 875 edit journal to a freshly bound store and logs the replay outcome.
    @MainActor
    private static func attachLaunchJournal(
        _ store: WorkspaceStore, journalURL: URL, binaryURL: URL, log: (String) -> Void
    ) throws {
        let report = try store.attachEditJournal(at: journalURL, launchPath: binaryURL)
        let detail = journalLaunchDetail(report, rotationFailure: store.editJournal?.failure)
        log("edit journal \(journalURL.path): \(detail)")
    }

    static func journalLaunchDetail(_ report: EditJournalReport, rotationFailure: String?) -> String {
        var detail = "replayed \(report.replayed) records"
        if report.alreadyApplied {
            if let failure = rotationFailure {
                detail = "already applied; journal rotation failed: \(failure)"
            } else {
                // Reattachment may retain the original replay base rather than rotate.
                detail = "already applied; journal attached"
            }
        }
        if let tail = report.tornTail {
            detail += "; torn tail of \(tail.length) bytes at offset \(tail.offset) skipped"
        }
        if (report.replayed > 0 || report.alreadyApplied) && !report.priorAcknowledgmentsVerified {
            detail += "; prior acknowledgments cannot be verified"
        }
        return detail
    }

    /// Called only from `startHeadlessSession` (the binary MCP launch), after a successful
    /// edit-journal attach/replay; the package launch path and the shared `makeBoundStore`
    /// callers stay unchanged.
    @MainActor
    static func scheduleNavigatorForBinaryLaunch(in store: WorkspaceStore) {
        store.navigatorAnalysisDidLand(in: store.snapshot.primarySlot, previousFingerprint: nil)
    }

    private static func validateBinaryIdentity(
        _ fingerprint: WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint
    ) throws {
        let canonicalURL = URL(fileURLWithPath: fingerprint.canonicalPath)
            .resolvingSymlinksInPath().standardizedFileURL
        guard canonicalURL.path == fingerprint.canonicalPath else {
            throw MCPLauncherError.binaryIdentityChanged
        }
        var metadata = stat()
        guard stat(canonicalURL.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              UInt64(metadata.st_dev) == fingerprint.device,
              UInt64(metadata.st_ino) == fingerprint.inode,
              Int64(metadata.st_size) == fingerprint.size,
              Int64(metadata.st_mtimespec.tv_sec) == fingerprint.modificationSeconds,
              Int64(metadata.st_mtimespec.tv_nsec) == fingerprint.modificationNanoseconds,
              Int64(metadata.st_ctimespec.tv_sec) == fingerprint.changeSeconds,
              Int64(metadata.st_ctimespec.tv_nsec) == fingerprint.changeNanoseconds else {
            throw MCPLauncherError.binaryIdentityChanged
        }
    }

    /// Binary fingerprints, analysis and binding verification run off MainActor.
    /// Store construction, package restore and edit-journal attach remain on MainActor.
    @MainActor
    static func run(binaryURL: URL, journalURL: URL? = nil, sliceArchitecture: String? = nil) -> Never {
        do {
            let protocolOutput = try HeadlessProtocolIO.isolateStandardOutput()
            MCPFatalSignalReporter.installForLaunch()
            let server: MCPServer
            let gate: MCPStartupGate
            if isWorkspacePackage(binaryURL) {
                guard sliceArchitecture == nil else { throw MCPLauncherError.sliceWithWorkspacePackage }
                // The package carries its own input bytes; there is no launch file to guard.
                // Package I/O stays in the headless scripting document layer (no GUI
                // document session exists in this process), next to open-workspace.
                MCPFatalSignalReporter.note(.openingPackage)
                let store = try WorkspaceScriptingAPI.openLaunchWorkspacePackage(at: binaryURL)
                if let journalURL {
                    try attachLaunchJournal(store, journalURL: journalURL, binaryURL: binaryURL,
                                            log: MCPStartupLog.line)
                }
                gate = .ready(api: WorkspaceScriptingAPI(store: store,
                    nativeDecompiler: NativeDecompilerRuntimeRegistry.productionShared))
                var packageServer = MCPServer(startup: gate, configuration: MCPToolListingProfile.launchConfiguration())
                packageServer.timing = MCPRequestTiming.selected(
                    environment: ProcessInfo.processInfo.environment, observer: MCPRequestTimingRecorder())
                server = packageServer
                MCPFatalSignalReporter.note(.ready)
            } else {
                let launched = startHeadlessSession(binaryURL: binaryURL, journalURL: journalURL,
                                                    sliceArchitecture: sliceArchitecture)
                server = launched.server
                gate = launched.gate
            }
            Task { @MainActor in
                await server.runStdioLoopAsync(output: protocolOutput)
                MCPFatalSignalReporter.prepareAlternateStack()
                try? protocolOutput.close()
                if !gate.status.isSettled {
                    gate.status.requestCancel()
                    MCPStartupLog.line("input closed before analysis finished (phase \(gate.status.snapshot().phase?.rawValue ?? "none")); exiting")
                    exit(0)
                }
                exit(gate.exitStatus)
            }
            dispatchMain()
        } catch {
            FileHandle.standardError.write(Data("MacScope MCP: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
