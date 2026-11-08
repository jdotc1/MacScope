import Foundation

// DC2-4: presenter/view side of crash-frame naming. `CrashFrameNameDisplay` is the pure row-model
// helper (no view, no window); `CrashFrameNamingModel` runs DC2-2's symbolicator off the main
// actor and publishes each frame's typed outcome. No MCP surface (orchestrator ruling Q2 (a)).

/// What a frame row shows about the host-cache name, derived only from the typed outcome.
enum CrashFrameNameDisplay: Equatable {
    /// Cache name(s) and +offset, labelled as from the host cache. `reportedSymbol` is set only
    /// when the report already had a symbol that differs from every cache name; both are shown.
    case named(names: [String], offset: UInt64, reportedSymbol: String?)
    /// No name; a one-line typed reason. Never a guessed name.
    case notNamed(reason: String)

    /// nil means: add nothing (the row keeps its existing text). That is the case for the app's own
    /// images, whose "Load the binary with this UUID" message must stay unchanged.
    static func make(outcome: FrameSymbolOutcome, reportedSymbol: String?) -> CrashFrameNameDisplay? {
        switch outcome {
        case .named(let frame):
            let names = frame.names.map(\.display)
            let differs = reportedSymbol.flatMap { reported in names.contains(reported) ? nil : reported }
            return .named(names: names, offset: frame.offsetWithinSymbol, reportedSymbol: differs)
        case .imageNotInCache(let info):
            // The app's own and other non-cache images keep their existing message.
            if let source = info.skippedSource, source != .sharedCache, source != .sharedCacheLibrary { return nil }
            return .notNamed(reason: "not named: image not in the host cache")
        case .cacheMismatch(let reason):
            return .notNamed(reason: "not named: " + mismatchText(reason))
        case .noSymbolCovering(let reason):
            return .notNamed(reason: "not named: " + noSymbolText(reason))
        case .ambiguous:
            return .notNamed(reason: "not named: image is ambiguous in the host cache")
        case .malformed(let reason):
            return .notNamed(reason: "not named: " + malformedText(reason))
        case .cancelled:
            return .notNamed(reason: "not named: cancelled")
        }
    }

    /// The single line a row shows.
    var text: String {
        switch self {
        case .named(let names, let offset, let reported):
            let base = "Host cache: " + names.joined(separator: " / ") + " + " + String(offset, radix: 16).withHexPrefix
            if let reported { return base + " (report says \(reported))" }
            return base
        case .notNamed(let reason):
            return reason
        }
    }

    private static func mismatchText(_ reason: CacheMismatchReason) -> String {
        switch reason {
        case .osBuildDiffers: "report is from a different OS build"
        case .hostBuildUnavailable: "host OS build unavailable"
        case .hostBuildSourcesDisagree: "host OS build sources disagree"
        case .slideInconsistent: "inconsistent image slide"
        case .catalogHeaderDisagree: "cache image identity disagrees"
        case .snapshotUnavailable(let why, _): "host cache unavailable (\(why.rawValue))"
        case .catalogScanIncomplete: "host cache scan incomplete"
        }
    }

    private static func noSymbolText(_ reason: NoSymbolReason) -> String {
        switch reason {
        case .startUnnamed: "no exported name at the function start"
        case .noFunctionBounds: "function bounds unknown"
        case .stubSection: "stub section"
        case .notExecutableCode: "not executable code"
        case .outsideAnyImage: "address in no cache image"
        case .beforeFirstFunction: "before the first function"
        case .pastLastFunction: "past the last function"
        case .exportsIncomplete: "export list incomplete"
        case .interiorSymbolOnly: "only an interior symbol found"
        }
    }

    private static func malformedText(_ reason: MalformedSymbolReason) -> String {
        switch reason {
        case .missingImageIndex, .imageIndexOutOfRange: "frame has no valid image"
        case .missingOffset: "frame has no image offset"
        case .invalidReportUUID: "report image UUID invalid"
        case .addressOverflow: "address overflow"
        case .traversalBound: "image data exceeds a safety bound"
        case .nameNotUTF8: "symbol name is not valid text"
        case .invalidLoadCommands: "image load commands invalid"
        }
    }
}

private extension String {
    var withHexPrefix: String { "0x" + self }
}

/// Runs the symbolicator off the main actor and publishes per-frame outcomes. One run per model;
/// `cancel()` (called when the window closes) stops it at the next cancellation check.
@MainActor
final class CrashFrameNamingModel: ObservableObject {
    struct Key: Hashable {
        let threadID: Int
        let frameID: Int
    }

    /// Runs off the main actor. `isCancelled` is safe to call from the work's own thread.
    typealias Work = @Sendable (CrashReport, @escaping @Sendable () -> Bool) -> Result<CrashSymbolication, CacheUnavailableError>

    @Published private(set) var outcomes: [Key: FrameSymbolOutcome] = [:]
    /// One line for the whole report when nothing was attempted or the host cache is unavailable.
    @Published private(set) var note: String?
    @Published private(set) var isRunning = false

    private let work: Work
    private var task: Task<Void, Never>?

    init(work: @escaping Work = CrashFrameNamingModel.hostCacheWork) {
        self.work = work
    }

    func start(report: CrashReport) {
        guard task == nil else { return }
        isRunning = true
        let work = self.work
        task = Task.detached(priority: .utility) { [weak self] in
            let result = work(report, { Task.isCancelled })
            guard !Task.isCancelled else { return }
            await self?.finish(result)
        }
    }

    func cancel() {
        task?.cancel()
        isRunning = false
    }

    private func finish(_ result: Result<CrashSymbolication, CacheUnavailableError>) {
        defer { isRunning = false }
        guard task?.isCancelled == false else { return }
        switch result {
        case .failure(let error):
            note = "System frames not named: host cache unavailable (\(error.reason.rawValue))"
        case .success(let symbolication):
            if let refusal = symbolication.refusal {
                switch refusal {
                case .tooManyFrames, .tooManyImages: note = "System frames not named: report exceeds the naming size limit"
                }
                return
            }
            var map: [Key: FrameSymbolOutcome] = [:]
            for frame in symbolication.frames {
                map[Key(threadID: frame.threadIndex, frameID: frame.frameID)] = frame.outcome
            }
            outcomes = map
        }
    }

    /// Production work: the host cache and host build, as DC2-2 expects. Not used by tests.
    nonisolated static let hostCacheWork: Work = { report, isCancelled in
        #if arch(arm64)
        let architecture = "arm64"
        #else
        let architecture = "x86_64"
        #endif
        do {
            let located = try HostCacheLocator().locate(importerArchitecture: architecture)
            let snapshot = try HostCacheSnapshot.open(
                mainURL: located.url, expectedArchitecture: located.architecture, isCancelled: isCancelled)
            let symbolicator = CrashFrameSymbolicator(snapshot: snapshot, hostBuild: HostBuildEvidence.current())
            return .success(symbolicator.symbolicate(report, isCancelled: isCancelled))
        } catch let error as CacheUnavailableError {
            return .failure(error)
        } catch {
            return .failure(CacheUnavailableError(.unreadable, "cache admission failed"))
        }
    }
}
