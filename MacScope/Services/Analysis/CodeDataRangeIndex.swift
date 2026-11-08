/// Union of valid half-open loader intervals. No instructions or range kinds
/// are retained; the original loader records remain snapshot authority.
struct CodeDataRangeIndex: Sendable {
    private struct Interval: Sendable {
        let lower: UInt64
        let upper: UInt64
    }
    private let intervals: [Interval]
    let validRangeCount: Int
    var intervalCount: Int { intervals.count }

    init(ranges: [BinaryCodeDataRange]) {
        let valid = ranges.compactMap { range -> Interval? in
            guard range.size > 0 else { return nil }
            let (end, overflow) = range.address.addingReportingOverflow(range.size)
            guard !overflow else { return nil }
            return Interval(lower: range.address, upper: end)
        }.sorted { $0.lower < $1.lower }
        validRangeCount = valid.count
        var merged: [Interval] = []
        for next in valid {
            if let current = merged.last, next.lower <= current.upper {
                merged[merged.count - 1] = Interval(lower: current.lower,
                    upper: max(current.upper, next.upper))
            } else {
                merged.append(next)
            }
        }
        intervals = merged
    }

    func contains(address: UInt64) -> Bool {
        var comparisons = 0
        return countedContains(address: address, comparisons: &comparisons)
    }

    /// Test seam counts actual endpoint comparisons in the same search.
    func countedContains(address: UInt64, comparisons: inout Int) -> Bool {
        var low = 0
        var high = intervals.count
        while low < high {
            let middle = low + (high - low) / 2
            let interval = intervals[middle]
            comparisons += 1
            if address < interval.lower {
                high = middle
            } else {
                comparisons += 1
                if address < interval.upper { return true }
                low = middle + 1
            }
        }
        return false
    }
}
