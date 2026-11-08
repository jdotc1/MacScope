import Foundation
@testable import MacScope

/// Test-only trust root. The product flag and product file loader are not consulted.
enum C2OwnReturnAuthority {
    static let environmentKey = "MACSCOPE_C2_OWN_RETURN_AUTHORITY"
    typealias Source = OwnReturnAuthority.Source
    typealias Image = OwnReturnAuthority.Image
    typealias Candidate = OwnReturnAuthority.Candidate
    typealias Row = OwnReturnAuthority.Row
    typealias Envelope = OwnReturnAuthority.Envelope
    typealias DisplacedImported = OwnReturnAuthority.DisplacedImported
    typealias Report = OwnReturnAuthority.Report
    typealias Result = OwnReturnAuthority.Result
    typealias Rejection = OwnReturnAuthority.Rejection
    struct Expectation {
        var source: Source
        var evidenceCensusHead: String
        var image: Image
        var slot: String
        var records: [Row]
        static var reviewed: Self {
            .init(source: C2OwnReturnExpectedCatalog.source,
                  evidenceCensusHead: C2OwnReturnExpectedCatalog.evidenceCensusHead,
                  image: C2OwnReturnExpectedCatalog.image, slot: C2OwnReturnExpectedCatalog.slot,
                  records: C2OwnReturnExpectedCatalog.records)
        }
    }

    static func load(into snapshot: WorkspaceSnapshot,
                     environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Result {
        guard let path = environment[environmentKey] else {
            return Result(snapshot: snapshot, report: nil)
        }
        guard !path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Rejection("empty authority path")
        }
        return try applying(data: Data(contentsOf: URL(fileURLWithPath: path)),
                            to: snapshot, expected: .reviewed)
    }

    static func applying(data: Data, to snapshot: WorkspaceSnapshot,
                         expected: Expectation) throws -> Result {
        try OwnReturnAuthority.applying(data: data, to: snapshot,
            expected: .init(source: expected.source, evidenceCensusHead: expected.evidenceCensusHead,
                            image: expected.image, slot: expected.slot, records: expected.records))
    }
}
