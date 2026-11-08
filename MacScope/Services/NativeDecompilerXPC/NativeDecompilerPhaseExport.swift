import Foundation

/// Launch-gated, unmasked JSONL export of finished phase Summaries (CR07). Active only when
/// MACSCOPE_NATIVE_PHASE_TRACE is on AND MACSCOPE_NATIVE_PHASE_EXPORT_PATH is an absolute path.
/// Best effort: file errors are swallowed (one stderr line) and never reach the decompile path.
final class NativeDecompilerPhaseExport: @unchecked Sendable {
    static let pathVariable = "MACSCOPE_NATIVE_PHASE_EXPORT_PATH"

    /// One line per finished attempt. Arrays are indexed by the named Phase/Counter order.
    struct Line: Codable, Equatable {
        let ordinal: UInt64
        let attemptID: UUID
        let elapsedNanoseconds: UInt64
        let durations: [UInt64]
        let counts: [UInt64]
        let counterObserved: [Bool]
        let completedSpans: [UInt64]
        let suppressedSpans: UInt64
        let unfinishedSpans: UInt64
        let exclusiveDurations: [UInt64]
        let coveredNanoseconds: UInt64
        let residualNanoseconds: UInt64
        let overlappingSpans: Bool
        let droppedIntervals: UInt64
        let attributionComplete: Bool
        let phaseNames: [String]
        let counterNames: [String]

        init(ordinal: UInt64, _ summary: NativeDecompilerPhaseRecord.Summary) {
            self.ordinal = ordinal
            attemptID = summary.attemptID
            elapsedNanoseconds = summary.elapsedNanoseconds
            durations = summary.durations
            counts = summary.counts
            counterObserved = summary.counterObserved
            completedSpans = summary.completedSpans
            suppressedSpans = summary.suppressedSpans
            unfinishedSpans = summary.unfinishedSpans
            exclusiveDurations = summary.exclusiveDurations
            coveredNanoseconds = summary.coveredNanoseconds
            residualNanoseconds = summary.residualNanoseconds
            overlappingSpans = summary.overlappingSpans
            droppedIntervals = summary.droppedIntervals
            attributionComplete = summary.attributionComplete
            phaseNames = NativeDecompilerPhaseRecord.Phase.allCases.map { "\($0)" }
            counterNames = NativeDecompilerPhaseRecord.Counter.allCases.map { "\($0)" }
        }
    }

    /// Resolved once per process, like `launchEnabled`; nil means no behavior change.
    static let launchSink: (@Sendable (NativeDecompilerPhaseRecord.Summary) -> Void)? = {
        makeSink(environment: ProcessInfo.processInfo.environment,
                 traceEnabled: NativeDecompilerPhaseRecord.launchEnabled)
    }()

    static func makeSink(
        environment: [String: String], traceEnabled: Bool
    ) -> (@Sendable (NativeDecompilerPhaseRecord.Summary) -> Void)? {
        guard traceEnabled, let path = environment[pathVariable], path.hasPrefix("/") else {
            return nil
        }
        let export = NativeDecompilerPhaseExport(path: path)
        return { export.write($0) }
    }

    private let path: String
    private let lock = NSLock()
    private var ordinal: UInt64 = 0
    private var reportedFailure = false

    init(path: String) { self.path = path }

    func write(_ summary: NativeDecompilerPhaseRecord.Summary) {
        lock.withLock {
            ordinal += 1
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys]
                var data = try encoder.encode(Line(ordinal: ordinal, summary))
                data.append(0x0A)
                if !FileManager.default.fileExists(atPath: path) {
                    guard FileManager.default.createFile(atPath: path, contents: nil) else {
                        throw CocoaError(.fileWriteUnknown)
                    }
                }
                let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
                defer { try? handle.close() }
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
            } catch {
                guard !reportedFailure else { return }
                reportedFailure = true
                FileHandle.standardError.write(
                    Data("native-phase export failed; further failures suppressed\n".utf8))
            }
        }
    }
}
