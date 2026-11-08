import Foundation

/// Pure builder for the appended Stage A extension block (item 1326).
///
/// Format: `work v1 analysis=<state> field=value,...` written after the legacy
/// attribution keys. Keys are the `StartupWorkCounters.Field` case names in declaration
/// order; only complete fields appear. `misuse` closes the block when it is valid.
/// Returns nil when no extension record exists (no recorder, or analysis never entered).
enum StartupWorkReport {
    static func block(for snapshot: StartupWorkCounters.Snapshot?) -> String? {
        guard let snapshot, snapshot.analysis != .notEntered else { return nil }
        var parts: [String] = []
        for field in StartupWorkCounters.Field.allCases {
            if let value = snapshot.values[field] { parts.append("\(field.name)=\(value)") }
        }
        if let misuse = snapshot.misuse { parts.append("workMisuse=\(misuse)") }
        return "work v1 analysis=\(snapshot.analysis.rawValue) [\(parts.joined(separator: ","))]"
    }
}
