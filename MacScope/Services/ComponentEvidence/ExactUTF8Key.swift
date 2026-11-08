// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/ComponentMatcher.swift (the ExactUTF8Key helper).
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: extracted into its own file, internal access, raw-byte initializer, no Codable,
// RelativePath and PathRange added.

import Foundation

extension ComponentEvidence {
    /// Owned bytes with byte equality, hash and order. No normalization or case folding.
    struct ExactUTF8Key: Hashable, Comparable, Sendable {
        let bytes: [UInt8]
        init(_ value: String) { bytes = Array(value.utf8) }
        /// Raw filesystem bytes that may not decode as UTF-8.
        init(rawBytes: [UInt8]) { bytes = rawBytes }
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.bytes.lexicographicallyPrecedes(rhs.bytes) }
        /// Valid UTF-8 text, or nil. Never a replacement-character decode.
        var text: String? { String(bytes: bytes, encoding: .utf8) }
        /// Reversible escaped rendering for display only; never an identity key.
        var display: String {
            var out = ""
            for byte in bytes {
                if byte >= 0x20, byte < 0x7f, byte != 0x5c { out.append(Character(UnicodeScalar(byte))) }
                else { out += "\\x" + (byte < 16 ? "0" : "") + String(byte, radix: 16) }
            }
            return out
        }
    }

    /// Slash-separated nonempty raw components; no NUL, slash, dot or dot-dot component.
    struct RelativePath: Hashable, Comparable, Sendable {
        static let maximumBytes = 4096
        let components: [ExactUTF8Key]

        init(components: [ExactUTF8Key]) throws {
            guard !components.isEmpty else { throw EvidenceError.unsafePath(nil) }
            for component in components where !Self.isSafe(component.bytes) {
                throw EvidenceError.unsafePath(PathRange(kind: .exactLeaf, path: RelativePath(unchecked: components)))
            }
            self.components = components
        }
        init(_ string: String) throws {
            try self.init(components: string.utf8.split(separator: 0x2f, omittingEmptySubsequences: false)
                .map { ExactUTF8Key(rawBytes: Array($0)) })
        }
        /// Components already validated by a checked initializer.
        init(unchecked components: [ExactUTF8Key]) { self.components = components }
        func prefix(_ count: Int) -> RelativePath { RelativePath(unchecked: Array(components.prefix(count))) }

        static func joined(_ components: [ExactUTF8Key]) -> [UInt8] {
            var out: [UInt8] = []
            for (index, component) in components.enumerated() {
                if index > 0 { out.append(0x2f) }
                out += component.bytes
            }
            return out
        }
        static func isSafe(_ bytes: [UInt8]) -> Bool {
            !bytes.isEmpty && bytes != [0x2e] && bytes != [0x2e, 0x2e] && !bytes.contains(0) && !bytes.contains(0x2f)
        }
        /// Joined bytes with `/` separators.
        var bytes: [UInt8] {
            var out: [UInt8] = []
            for (index, component) in components.enumerated() {
                if index > 0 { out.append(0x2f) }
                out += component.bytes
            }
            return out
        }
        var byteCount: Int { components.reduce(components.count - 1) { $0 + $1.bytes.count } }
        var key: ExactUTF8Key { ExactUTF8Key(rawBytes: bytes) }
        var text: String? { key.text }
        var display: String { key.display }
        var parent: RelativePath? { components.count > 1 ? RelativePath(unchecked: Array(components.dropLast())) : nil }
        var last: ExactUTF8Key { components[components.count - 1] }

        func appending(_ component: ExactUTF8Key) throws -> RelativePath {
            try RelativePath(components: components + [component])
        }
        /// Component-boundary prefix test: `a/b` is a prefix of `a/b` and `a/b/c`, never of `a/bc`.
        func hasPrefix(_ other: RelativePath) -> Bool {
            components.count >= other.components.count && Array(components.prefix(other.components.count)) == other.components
        }
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.bytes.lexicographicallyPrecedes(rhs.bytes) }
    }

    /// Exactly one of an exact leaf, a subtree, or the whole root.
    struct PathRange: Hashable, Sendable {
        enum Kind: Hashable, Sendable { case exactLeaf, subtree, wholeRoot }
        let kind: Kind
        let path: RelativePath?
        static let wholeRoot = PathRange(kind: .wholeRoot, path: nil)
        static func leaf(_ path: RelativePath) -> PathRange { .init(kind: .exactLeaf, path: path) }
        static func subtree(_ path: RelativePath) -> PathRange { .init(kind: .subtree, path: path) }

        /// Whether the range hides `candidate` by component boundary.
        func blocks(_ candidate: RelativePath) -> Bool {
            switch kind {
            case .wholeRoot: true
            case .exactLeaf: path == candidate
            case .subtree: path.map { candidate.hasPrefix($0) } ?? true
            }
        }
        var display: String {
            switch kind {
            case .wholeRoot: "[root]"
            case .exactLeaf: path?.display ?? "[leaf]"
            case .subtree: (path?.display ?? "") + "/**"
            }
        }
    }
}
