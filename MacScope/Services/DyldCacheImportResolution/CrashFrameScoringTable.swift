import Foundation

/// DC2 acceptance scoring: one row per frame of the crashed thread, comparing the report's own
/// `symbol`/`symbolLocation` (the OS's symbolication, the oracle) with `CrashFrameSymbolicator`'s
/// typed answer. `CrashFrameSymbolicator` never reads the report's symbol fields, so the oracle is
/// independent. Pure value logic over a finished `CrashSymbolication`; nothing here reads a cache.
struct CrashFrameScoringTable: Codable, Equatable, Sendable {
    enum Verdict: String, Codable, CaseIterable, Sendable {
        case match, mismatch, typedUnnamed, oracleUnnamed
    }

    struct Row: Codable, Equatable, Sendable {
        var frameIndex: Int
        var imageName: String?
        var imageUUID: String?
        var imageOffset: UInt64?
        var oracleSymbol: String?
        var oracleSymbolLocation: UInt64?
        /// Case name of `FrameSymbolOutcome`, for example `named` or `imageNotInCache`.
        var outcome: String
        /// Typed refusal payload for every non-named outcome.
        var reason: String?
        var macscopeNames: [String]
        var offsetWithinSymbol: UInt64?
        var verdict: Verdict
        /// Why a `mismatch` is one: which field differed.
        var mismatchDetail: String?
    }

    static let normalizationNote =
        "Names compare equal after exactly one normalization: one leading '_' is stripped from the MacScope name when the oracle symbol lacks that underscore (Mach-O '___pthread_kill' is reported as '__pthread_kill'); a name equal to the oracle symbol also matches without stripping. symbolLocation must equal offsetWithinSymbol exactly. Precedence: oracleUnnamed (report has no symbol) first, then typedUnnamed (MacScope did not name), then match/mismatch."

    var processName: String
    var reportOSBuild: String?
    var threadIndex: Int
    var normalization: String
    var cacheUUID: String?
    var frameTotal: Int
    var verdictCounts: [String: Int]
    var rows: [Row]

    var countsSumToTotal: Bool { verdictCounts.values.reduce(0, +) == frameTotal && rows.count == frameTotal }

    static func build(
        report: CrashReport, threadIndex: Int, symbolication: CrashSymbolication
    ) -> CrashFrameScoringTable? {
        guard let thread = report.threads.first(where: { $0.id == threadIndex }) else { return nil }
        var counts = Dictionary(uniqueKeysWithValues: Verdict.allCases.map { ($0.rawValue, 0) })
        var rows: [Row] = []
        for frame in thread.frames {
            let record = symbolication.frames.first { $0.threadIndex == thread.id && $0.frameID == frame.id }
            let image = frame.imageIndex.flatMap { report.images.indices.contains($0) ? report.images[$0] : nil }
            var row = Row(
                frameIndex: frame.id, imageName: image?.name, imageUUID: image?.uuid,
                imageOffset: frame.imageOffset, oracleSymbol: frame.reportedSymbol,
                oracleSymbolLocation: frame.symbolLocation, outcome: "", reason: nil,
                macscopeNames: [], offsetWithinSymbol: nil, verdict: .typedUnnamed, mismatchDetail: nil)
            if let record {
                fill(&row, outcome: record.outcome)
            } else if let refusal = symbolication.refusal {
                row.outcome = "refused"
                row.reason = String(describing: refusal)
            } else {
                row.outcome = "noRecord"
                row.reason = "the symbolicator returned no record for this frame"
            }
            row.verdict = verdict(for: &row)
            counts[row.verdict.rawValue, default: 0] += 1
            rows.append(row)
        }
        return CrashFrameScoringTable(
            processName: report.processName, reportOSBuild: report.osVersion?.build, threadIndex: thread.id,
            normalization: normalizationNote, cacheUUID: hex(symbolication.cacheUUID),
            frameTotal: rows.count, verdictCounts: counts, rows: rows)
    }

    private static func verdict(for row: inout Row) -> Verdict {
        guard let oracle = row.oracleSymbol, !oracle.isEmpty else { return .oracleUnnamed }
        guard row.outcome == "named" else { return .typedUnnamed }
        var problems: [String] = []
        let nameMatches = row.macscopeNames.contains { name in
            name == oracle || (name.hasPrefix("_") && String(name.dropFirst()) == oracle)
        }
        if !nameMatches { problems.append("name: oracle '\(oracle)' not in MacScope names") }
        if row.oracleSymbolLocation != row.offsetWithinSymbol {
            let reported = row.oracleSymbolLocation.map(String.init) ?? "absent"
            let ours = row.offsetWithinSymbol.map(String.init) ?? "absent"
            problems.append("offset: oracle symbolLocation \(reported) vs MacScope \(ours)")
        }
        if problems.isEmpty { return .match }
        row.mismatchDetail = problems.joined(separator: "; ")
        return .mismatch
    }

    private static func fill(_ row: inout Row, outcome: FrameSymbolOutcome) {
        switch outcome {
        case .named(let frame):
            row.outcome = "named"
            row.macscopeNames = frame.names.map(\.display)
            row.offsetWithinSymbol = frame.offsetWithinSymbol
        case .imageNotInCache(let value):
            row.outcome = "imageNotInCache"
            row.reason = String(describing: value)
        case .cacheMismatch(let value):
            row.outcome = "cacheMismatch"
            row.reason = String(describing: value)
        case .noSymbolCovering(let value):
            row.outcome = "noSymbolCovering"
            row.reason = String(describing: value)
        case .ambiguous(let value):
            row.outcome = "ambiguous"
            row.reason = String(describing: value)
        case .malformed(let value):
            row.outcome = "malformed"
            row.reason = String(describing: value)
        case .cancelled:
            row.outcome = "cancelled"
        }
    }

    private static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}
