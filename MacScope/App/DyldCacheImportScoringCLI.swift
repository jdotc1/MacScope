#if DEBUG
import Darwin
import Foundation

/// DC1 acceptance harness (debug builds only):
/// `MacScope --score-host-cache-imports <binary> <output.json>` parses the binary (default slice
/// rule: host arm64), builds the slice-A import entries, runs the real host-cache resolver once and
/// writes the scoring table (one row per import, counts per outcome that sum to the total). Prints
/// one summary line. Exit 0 on success, 1 with a one-line stderr reason otherwise. No retry.
enum DyldCacheImportScoringCLI {
    static let flag = "--score-host-cache-imports"

    struct Request: Equatable {
        let binaryPath: String
        let outputPath: String
    }

    static func request(from arguments: [String]) -> Request? {
        guard arguments.dropFirst().first == flag, arguments.count == 4 else { return nil }
        return Request(binaryPath: arguments[2], outputPath: arguments[3])
    }

    static func run(_ request: Request) -> Never {
        do {
            guard request.binaryPath.hasPrefix("/"), request.outputPath.hasPrefix("/") else {
                throw Failure("paths must be absolute")
            }
            let binaryURL = URL(fileURLWithPath: request.binaryPath).standardizedFileURL
            let imported = try MachOImportService().importBinary(at: binaryURL)
            let machO = imported.machO
            let architecture = machO.architectureName
            let metadata = MachOLoadMetadata.from(machO)
            let entries = ImportResolutionRequestBuilder.build(from: metadata)
            let batch = DyldCacheImportResolver.resolve(entries: entries, importerArchitecture: architecture)
            let table = DyldCacheImportScoringTable.build(
                importer: imported.executableURL.path, architecture: architecture,
                entries: entries, batch: batch, dependencies: metadata.dependentDylibs)
            guard table.countsSumToTotal else { throw Failure("outcome counts do not sum to the import total") }
            try table.encoded().write(to: URL(fileURLWithPath: request.outputPath), options: .atomic)
            let counts = table.outcomeCounts.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
            print("score-host-cache-imports arch=\(architecture) total=\(table.importTotal) partial=\(table.isPartial) \(counts)")
            exit(0)
        } catch {
            FileHandle.standardError.write(Data("MacScope score-host-cache-imports: \(error)\n".utf8))
            exit(1)
        }
    }

    private struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }
}
#endif
