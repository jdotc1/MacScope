import Foundation

/// An address-independent fact. A missing value is unknown, not an empty value.
struct StructuralRecord: Codable, Equatable, Sendable {
    let key: String
    let value: String?
}

struct StructuralDifference: Codable, Equatable, Sendable {
    let key: String
    let original: String
    let rebuilt: String
}

struct StructuralUnassessed: Codable, Equatable, Sendable {
    let key: String
    let original: [StructuralRecord]
    let rebuilt: [StructuralRecord]
    let reason: String
}

struct StructuralResult: Codable, Equatable, Sendable {
    let matched: [StructuralRecord]
    let differing: [StructuralDifference]
    let missing: [StructuralRecord]
    let extra: [StructuralRecord]
    let unassessed: [StructuralUnassessed]
    let score: Double?
}

enum StructuralComparison {
    /// Duplicate keys and unknown values remain visible but are excluded from the denominator.
    static func compare(original: [StructuralRecord], rebuilt: [StructuralRecord]) -> StructuralResult {
        let old = Dictionary(grouping: original, by: \.key)
        let new = Dictionary(grouping: rebuilt, by: \.key)
        let keys = Set(old.keys).union(new.keys).sorted()
        var matched: [StructuralRecord] = []
        var differing: [StructuralDifference] = []
        var missing: [StructuralRecord] = []
        var extra: [StructuralRecord] = []
        var unassessed: [StructuralUnassessed] = []
        func order(_ records: [StructuralRecord]) -> [StructuralRecord] {
            records.sorted { ($0.value ?? "", $0.value == nil ? 0 : 1) < ($1.value ?? "", $1.value == nil ? 0 : 1) }
        }
        for key in keys {
            let lhs = order(old[key] ?? [])
            let rhs = order(new[key] ?? [])
            if lhs.count > 1 || rhs.count > 1 {
                unassessed.append(.init(key: key, original: lhs, rebuilt: rhs, reason: "duplicate identity"))
            } else if lhs.contains(where: { $0.value == nil }) || rhs.contains(where: { $0.value == nil }) {
                unassessed.append(.init(key: key, original: lhs, rebuilt: rhs, reason: "unknown value"))
            } else if let a = lhs.first, let b = rhs.first, let av = a.value, let bv = b.value {
                if av == bv { matched.append(a) }
                else { differing.append(.init(key: key, original: av, rebuilt: bv)) }
            } else if let a = lhs.first { missing.append(a) }
            else if let b = rhs.first { extra.append(b) }
        }
        let denominator = matched.count + differing.count + missing.count + extra.count
        return StructuralResult(matched: matched, differing: differing, missing: missing, extra: extra,
                                unassessed: unassessed,
                                score: denominator == 0 ? nil : Double(matched.count) / Double(denominator))
    }
}
