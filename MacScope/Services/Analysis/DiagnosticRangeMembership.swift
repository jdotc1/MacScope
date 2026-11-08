import Foundation

/// Pure union-interval membership over already-validated, nonempty half-open ranges.
///
/// Item 1330 (R33): helper only, not wired into any collector path. Overlapping or adjacent
/// ranges merge into one interval using comparisons and `max` only, so no endpoint is ever
/// computed by addition. The search inspects one interval per step and reports how many
/// interval-membership predicates it evaluated; that is the only count it keeps.
struct DiagnosticRangeMembership: Sendable {
    /// Sorted, disjoint, non-adjacent half-open intervals.
    let intervals: [Range<UInt64>]

    /// Empty ranges are not valid input and are skipped rather than merged.
    init(validatedRanges ranges: [Range<UInt64>]) {
        var merged: [Range<UInt64>] = []
        for range in ranges.filter({ !$0.isEmpty }).sorted(by: { $0.lowerBound < $1.lowerBound }) {
            if let last = merged.last, range.lowerBound <= last.upperBound {
                merged[merged.count - 1] = last.lowerBound..<Swift.max(last.upperBound, range.upperBound)
            } else {
                merged.append(range)
            }
        }
        intervals = merged
    }

    /// Membership plus the number of interval predicates visited (zero when there are none).
    func contains(_ address: UInt64) -> (isMember: Bool, visited: Int) {
        var low = 0
        var high = intervals.count
        var visited = 0
        while low < high {
            let middle = low + (high - low) / 2
            let interval = intervals[middle]
            visited += 1
            if address < interval.lowerBound {
                high = middle
            } else if address >= interval.upperBound {
                low = middle + 1
            } else {
                return (true, visited)
            }
        }
        return (false, visited)
    }
}
