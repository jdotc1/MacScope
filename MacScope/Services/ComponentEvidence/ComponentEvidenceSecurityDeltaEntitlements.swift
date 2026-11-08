// Original to this item (AR3, NF04). Converts frozen EntitlementValue trees to the report's exact Value domain and
// diffs two dictionaries key by key. Integer width is kept for DER (typed) and for nothing else: Foundation property
// lists and XML entitlements do not prove a signed or unsigned width, so their integers become normalizedInteger
// and a signed/unsigned comparison against a typed DER value stays representationUnresolved. Dictionary keys come
// from Swift Strings; byte-exactness of a Foundation-decoded key is not claimed here.

import Foundation

extension ComponentEvidenceSecurityDelta {
    enum EntitlementDelta {
        enum Kind: Sendable, Hashable { case unchanged, added, removed, changed, unresolved }

        struct Row: Sendable, Hashable {
            let key: ExactKey
            let kind: Kind
            let previous: Value?
            let current: Value?
            let reason: ReasonCode?
        }

        /// `typedIntegers` is true only for DER-sourced trees.
        static func convert(_ value: EntitlementValue, typedIntegers: Bool, depth: Int = 0,
                            nodes: inout Int) throws -> Value {
            nodes += 1
            guard depth <= ValueBudget.defaultMaximumDepth else { throw ValueError.limit(.typedDepthLimit) }
            guard nodes <= ValueBudget.defaultMaximumNodes else { throw ValueError.limit(.typedNodeLimit) }
            switch value {
            case .boolean(let flag): return .boolean(flag)
            case .integer(let number): return typedIntegers ? .signed(number) : .normalizedInteger(String(number))
            case .unsignedInteger(let number): return typedIntegers ? .unsigned(number) : .normalizedInteger(String(number))
            case .real(let number):
                guard number.isFinite else { throw ValueError.nonFiniteReal }
                return .realBits(number.bitPattern)
            case .string(let text): return .string(ExactKey(text: text))
            case .data(let data): return .data(data)
            case .date(let date):
                let seconds = date.timeIntervalSinceReferenceDate
                guard seconds.isFinite else { throw ValueError.nonFiniteDate }
                return .dateBits(seconds.bitPattern)
            case .array(let items):
                return .array(try items.map { try convert($0, typedIntegers: typedIntegers, depth: depth + 1, nodes: &nodes) })
            case .dictionary(let dictionary):
                let entries = try dictionary.entries.map {
                    ValueEntry(key: ExactKey(text: $0.key),
                               value: try convert($0.value, typedIntegers: typedIntegers, depth: depth + 1, nodes: &nodes))
                }
                return try ValueAlgebra.dictionary(entries)
            }
        }

        static func convertTop(_ value: EntitlementValue, typedIntegers: Bool) throws -> Value {
            var nodes = 0
            let converted = try convert(value, typedIntegers: typedIntegers, nodes: &nodes)
            try ValueAlgebra.validate(converted, budget: try ValueBudget())
            return converted
        }

        private static func failureReason(_ error: Error) -> ReasonCode {
            if let value = error as? ValueError, let cap = value.cap { return .cap(cap) }
            return .numericRepresentationUnspecified
        }

        /// Merge of two byte-sorted dictionaries. A key whose conversion or comparison cannot be decided is unresolved.
        static func diff(previous: EntitlementDictionary, current: EntitlementDictionary, previousTyped: Bool,
                         currentTyped: Bool) -> [Row] {
            let old = previous.entries, new = current.entries
            var rows: [Row] = []
            var i = 0, j = 0
            func one(_ entry: EntitlementEntry, typed: Bool) -> (Value?, ReasonCode?) {
                do { return (try convertTop(entry.value, typedIntegers: typed), nil) } catch { return (nil, failureReason(error)) }
            }
            while i < old.count || j < new.count {
                let order: Int
                if i == old.count { order = 1 } else if j == new.count { order = -1 } else {
                    order = old[i].key.utf8.lexicographicallyPrecedes(new[j].key.utf8) ? -1
                        : (new[j].key.utf8.lexicographicallyPrecedes(old[i].key.utf8) ? 1 : 0)
                }
                if order < 0 {
                    let (value, reason) = one(old[i], typed: previousTyped)
                    rows.append(Row(key: ExactKey(text: old[i].key), kind: reason == nil ? .removed : .unresolved,
                                    previous: value, current: nil, reason: reason))
                    i += 1
                } else if order > 0 {
                    let (value, reason) = one(new[j], typed: currentTyped)
                    rows.append(Row(key: ExactKey(text: new[j].key), kind: reason == nil ? .added : .unresolved,
                                    previous: nil, current: value, reason: reason))
                    j += 1
                } else {
                    let (a, reasonA) = one(old[i], typed: previousTyped)
                    let (b, reasonB) = one(new[j], typed: currentTyped)
                    let key = ExactKey(text: old[i].key)
                    if let a, let b {
                        let verdict = (try? ValueAlgebra.compare(previous: a, current: b, budget: try ValueBudget()))
                        switch verdict {
                        case .equal?: rows.append(Row(key: key, kind: .unchanged, previous: a, current: b, reason: nil))
                        case .different?: rows.append(Row(key: key, kind: .changed, previous: a, current: b, reason: nil))
                        default: rows.append(Row(key: key, kind: .unresolved, previous: a, current: b,
                                                  reason: .numericRepresentationUnspecified))
                        }
                    } else {
                        rows.append(Row(key: key, kind: .unresolved, previous: a, current: b, reason: reasonA ?? reasonB))
                    }
                    i += 1; j += 1
                }
            }
            return rows
        }
    }
}

extension ComponentEvidenceSecurityDelta.ValueBudget {
    static let defaultMaximumDepth = 32
    static let defaultMaximumNodes = 10_000
}
