// Original to this item (AR3, NF02). The exact typed value tree and its bounded comparison. Entitlement semantics
// stay with the frozen comparator; this algebra only decides whether two typed values are equal, different or
// whether their numeric representation cannot be resolved. No codec, no Foundation fidelity inference.

import Foundation

extension ComponentEvidenceSecurityDelta {
    /// Signed, unsigned and normalizedInteger are distinct. A normalized integer keeps uncertainty and never
    /// invents a source signedness. Real and date values are raw bits, so signed zero is preserved.
    indirect enum Value: Sendable, Hashable {
        case boolean(Bool)
        case signed(Int64)
        case unsigned(UInt64)
        case normalizedInteger(String)
        case realBits(UInt64)
        case string(ExactKey)
        case data(Data)
        case dateBits(UInt64)
        case array([Value])
        case dictionary([ValueEntry])
    }

    struct ValueEntry: Sendable, Hashable {
        let key: ExactKey
        let value: Value
    }

    enum ValueComparison: String, Sendable, Hashable { case equal, different, representationUnresolved }

    /// Defaults are the per-conversion limits. Tests reduce them; callers cannot raise the ceilings.
    struct ValueBudget: Sendable, Hashable {
        static let depthCeiling = 32
        static let nodeCeiling = 100_000
        static let byteCeiling = 16 * 1024 * 1024
        let maximumDepth: Int
        let maximumNodes: Int
        let maximumBytes: Int
        init(maximumDepth: Int = 32, maximumNodes: Int = 10_000, maximumBytes: Int = 65_536) throws {
            guard (1...Self.depthCeiling).contains(maximumDepth), (1...Self.nodeCeiling).contains(maximumNodes),
                  (0...Self.byteCeiling).contains(maximumBytes) else { throw ModelError.invalid(.invalidOptions) }
            self.maximumDepth = maximumDepth; self.maximumNodes = maximumNodes; self.maximumBytes = maximumBytes
        }
    }

    /// An invalid value is a typed invalid review; a reached bound is a named cap that the report boundary turns
    /// into PARTIAL. A caught cap is never turned into a complete empty value.
    enum ValueError: Error, Sendable, Hashable {
        case invalidNormalizedInteger
        case nonFiniteReal
        case nonFiniteDate
        case duplicateOrUnsortedKeys
        case limit(Cap)

        var cap: Cap? {
            guard case .limit(let reached) = self else { return nil }
            return reached
        }
    }

    enum ValueAlgebra {
        /// Canonical decimal: optional leading minus, no leading zeros, no negative zero, at least one digit.
        static func isCanonicalDecimal(_ text: String) -> Bool {
            var digits = Substring(text)
            let negative = digits.first == "-"
            if negative { digits = digits.dropFirst() }
            guard !digits.isEmpty, digits.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
            if digits.count > 1, digits.first == "0" { return false }
            return !(negative && digits == "0")
        }

        /// Sorts entries into exact UTF-8 key order and refuses duplicate keys.
        static func dictionary(_ entries: [ValueEntry]) throws -> Value {
            let sorted = entries.sorted { $0.key < $1.key }
            for pair in zip(sorted, sorted.dropFirst()) where pair.0.key == pair.1.key { throw ValueError.duplicateOrUnsortedKeys }
            return .dictionary(sorted)
        }

        /// Checks every invariant and every budget; returns normally only for a fully valid value.
        static func validate(_ value: Value, budget: ValueBudget) throws {
            var nodes = 0, bytes = 0
            try visit(value, depth: 1, budget: budget, nodes: &nodes, bytes: &bytes)
        }

        private static func visit(_ value: Value, depth: Int, budget: ValueBudget, nodes: inout Int, bytes: inout Int) throws {
            guard depth <= budget.maximumDepth else { throw ValueError.limit(.typedDepthLimit) }
            nodes += 1
            guard nodes <= budget.maximumNodes else { throw ValueError.limit(.typedNodeLimit) }
            func charge(_ count: Int) throws {
                bytes += count
                guard bytes <= budget.maximumBytes else { throw ValueError.limit(.decodedByteLimit) }
            }
            switch value {
            case .boolean, .signed, .unsigned: break
            case .normalizedInteger(let text):
                guard isCanonicalDecimal(text) else { throw ValueError.invalidNormalizedInteger }
                try charge(text.utf8.count)
            case .realBits(let bits): guard Double(bitPattern: bits).isFinite else { throw ValueError.nonFiniteReal }
            case .dateBits(let bits): guard Double(bitPattern: bits).isFinite else { throw ValueError.nonFiniteDate }
            case .string(let key): try charge(key.byteCount)
            case .data(let data): try charge(data.count)
            case .array(let items):
                for item in items { try visit(item, depth: depth + 1, budget: budget, nodes: &nodes, bytes: &bytes) }
            case .dictionary(let entries):
                for pair in zip(entries, entries.dropFirst()) where !(pair.0.key < pair.1.key) { throw ValueError.duplicateOrUnsortedKeys }
                for entry in entries {
                    try charge(entry.key.byteCount)
                    try visit(entry.value, depth: depth + 1, budget: budget, nodes: &nodes, bytes: &bytes)
                }
            }
        }

        /// Signed versus unsigned is different. Equal normalized magnitude against a typed integer is unresolved;
        /// different magnitudes are different. Arrays are ordered; real and date bits keep signed zero.
        static func compare(previous: Value, current: Value, budget: ValueBudget) throws -> ValueComparison {
            try validate(previous, budget: budget)
            try validate(current, budget: budget)
            return compareValidated(previous, current)
        }

        private static func decimal(_ value: Value) -> String? {
            switch value {
            case .signed(let number): String(number)
            case .unsigned(let number): String(number)
            case .normalizedInteger(let text): text
            default: nil
            }
        }

        private static func combine(_ parts: [ValueComparison]) -> ValueComparison {
            if parts.contains(.different) { return .different }
            return parts.contains(.representationUnresolved) ? .representationUnresolved : .equal
        }

        private static func compareValidated(_ lhs: Value, _ rhs: Value) -> ValueComparison {
            switch (lhs, rhs) {
            case (.boolean(let a), .boolean(let b)): return a == b ? .equal : .different
            case (.signed(let a), .signed(let b)): return a == b ? .equal : .different
            case (.unsigned(let a), .unsigned(let b)): return a == b ? .equal : .different
            case (.normalizedInteger(let a), .normalizedInteger(let b)): return a == b ? .equal : .different
            case (.realBits(let a), .realBits(let b)), (.dateBits(let a), .dateBits(let b)): return a == b ? .equal : .different
            case (.string(let a), .string(let b)): return a == b ? .equal : .different
            case (.data(let a), .data(let b)): return a == b ? .equal : .different
            case (.array(let a), .array(let b)):
                guard a.count == b.count else { return .different }
                return combine(zip(a, b).map { compareValidated($0, $1) })
            case (.dictionary(let a), .dictionary(let b)):
                guard a.count == b.count, zip(a, b).allSatisfy({ $0.key == $1.key }) else { return .different }
                return combine(zip(a, b).map { compareValidated($0.value, $1.value) })
            case (.normalizedInteger, .signed), (.normalizedInteger, .unsigned), (.signed, .normalizedInteger),
                 (.unsigned, .normalizedInteger):
                return decimal(lhs) == decimal(rhs) ? .representationUnresolved : .different
            default: return .different
            }
        }
    }

    // MARK: Boundary translation of upstream faults

    enum BoundaryTranslation: Sendable, Hashable {
        /// Cancellation is preserved and publishes nothing.
        case cancelled
        /// A value or binding the review cannot use.
        case invalidReview(RefusalCode)
        /// Evidence that could not be obtained; never an absence.
        case unavailable(UnderlyingKind)
    }

    enum BoundaryTranslator {
        static func kind(of problem: ComponentEvidence.SignatureEvidenceProblem) -> UnderlyingKind {
            switch problem {
            case .unsupportedArchitecture, .unsupportedDigestAlgorithm: .unsupported
            case .readFailed: .readFailed
            case .capReached: .budget
            case .structureRefused, .codeDirectoryHeaderTruncated, .codeDirectoryTypeMagicMismatch: .malformed
            case .notExamined: .unavailable
            }
        }

        static func translate(_ error: ComponentEvidence.SignatureCaptureError) -> BoundaryTranslation {
            switch error {
            case .cancelled: .cancelled
            case .unavailable, .shortRead: .unavailable(.readFailed)
            case .staleCapability, .changedInput: .unavailable(.stale)
            case .wrongSlice: .invalidReview(.evidenceBindingMismatch)
            case .invalidEvidence, .invalidLimits: .invalidReview(.invalidReview)
            case .invalidContainer: .unavailable(.malformed)
            }
        }
    }
}
