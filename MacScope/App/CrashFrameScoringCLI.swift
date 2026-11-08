#if DEBUG
import Darwin
import Foundation

/// DC2 acceptance harness (debug builds only):
/// `MacScope --score-crash-frames <report.ips> <output.json>` parses the crash report, runs the real
/// `CrashFrameSymbolicator` once over the host cache and writes the scoring table (one row per frame
/// of the crashed thread, verdict counts that sum to the frame total). Prints one summary line.
/// Exit 0 on success, 1 with a one-line stderr reason otherwise. No retry.
enum CrashFrameScoringCLI {
    static let flag = "--score-crash-frames"

    struct Request: Equatable {
        let reportPath: String
        let outputPath: String
    }

    static func request(from arguments: [String]) -> Request? {
        guard arguments.dropFirst().first == flag, arguments.count == 4 else { return nil }
        return Request(reportPath: arguments[2], outputPath: arguments[3])
    }

    static func run(_ request: Request) -> Never {
        do {
            guard request.reportPath.hasPrefix("/"), request.outputPath.hasPrefix("/") else {
                throw Failure("paths must be absolute")
            }
            let data = try Data(contentsOf: URL(fileURLWithPath: request.reportPath))
            let report = try CrashReport.parse(data)
            guard let crashed = report.threads.first(where: { $0.triggered }) else {
                throw Failure("the report has no triggered thread")
            }
            #if arch(arm64)
            let architecture = "arm64"
            #else
            let architecture = "x86_64"
            #endif
            let located = try HostCacheLocator().locate(importerArchitecture: architecture)
            let snapshot = try HostCacheSnapshot.open(mainURL: located.url, expectedArchitecture: located.architecture)
            let symbolicator = CrashFrameSymbolicator(snapshot: snapshot, hostBuild: HostBuildEvidence.current())
            let symbolication = symbolicator.symbolicate(report)
            guard let table = CrashFrameScoringTable.build(
                report: report, threadIndex: crashed.id, symbolication: symbolication)
            else { throw Failure("the crashed thread is missing from the report") }
            guard table.countsSumToTotal else { throw Failure("verdict counts do not sum to the frame total") }
            try table.encoded().write(to: URL(fileURLWithPath: request.outputPath), options: .atomic)
            let counts = table.verdictCounts.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
            print("score-crash-frames thread=\(table.threadIndex) total=\(table.frameTotal) \(counts)")
            exit(0)
        } catch {
            FileHandle.standardError.write(Data("MacScope score-crash-frames: \(error)\n".utf8))
            exit(1)
        }
    }

    private struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }
}
#endif
