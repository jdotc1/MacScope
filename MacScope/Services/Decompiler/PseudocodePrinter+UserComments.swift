import Foundation

/// Why an authored comment could not be rendered above a statement (E2).
public enum PseudocodeUnplacedCommentReason: String, Hashable, Sendable {
    /// The address is a body instruction, but no emitted statement carries it as its exact source
    /// address: the instruction was folded into another statement, or removed as dead.
    case folded
    /// The address is marked data or undefined (or lies in a loader data range), so it is not code.
    case excludedFromCode
    /// The address is inside the function but is not the start of any decoded instruction.
    case noInstruction
}

public struct PseudocodeUnplacedComment: Hashable, Sendable {
    public var address: UInt64
    public var text: String
    public var reason: PseudocodeUnplacedCommentReason

    public init(address: UInt64, text: String, reason: PseudocodeUnplacedCommentReason) {
        self.address = address
        self.text = text
        self.reason = reason
    }
}

/// The authored comments for ONE function, already restricted to that function's address range,
/// plus the facts needed to classify a comment that cannot be placed.
public struct PseudocodeUserComments: Hashable, Sendable {
    public var textByAddress: [UInt64: String]
    /// Addresses of the instructions that form the function body handed to the printer.
    public var bodyAddresses: Set<UInt64>
    /// Addresses excluded from code (data / undefined marks, loader data ranges).
    public var excludedAddresses: Set<UInt64>

    public static let none = PseudocodeUserComments(textByAddress: [:])

    public init(
        textByAddress: [UInt64: String],
        bodyAddresses: Set<UInt64> = [],
        excludedAddresses: Set<UInt64> = []
    ) {
        self.textByAddress = textByAddress
        self.bodyAddresses = bodyAddresses
        self.excludedAddresses = excludedAddresses
    }

    public var isEmpty: Bool { textByAddress.isEmpty }
}

extension PseudocodePrinter {
    /// Renders one authored comment as the text of consecutive `// ` source lines (OQ-5).
    /// CR, LF and CRLF split lines. Every other control character, U+0085, U+2028 and U+2029 become a
    /// space, so no raw line or paragraph separator reaches the output. Trailing blanks are dropped.
    static func userCommentSegments(_ text: String) -> [String] {
        var segments: [String] = []
        var current = String.UnicodeScalarView()
        var previousWasCR = false
        func flush() {
            var segment = String(current)
            while segment.last == " " { segment.removeLast() }
            segments.append(segment)
            current = String.UnicodeScalarView()
        }
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 0x0A:
                if !previousWasCR { flush() }
                previousWasCR = false
            case 0x0D:
                flush()
                previousWasCR = true
            default:
                previousWasCR = false
                let value = scalar.value
                if value < 0x20 || (0x7F...0x9F).contains(value) || value == 0x2028 || value == 0x2029 {
                    current.append(" ")
                } else {
                    current.append(scalar)
                }
            }
        }
        flush()
        return segments
    }

    /// The E2 post-pass. Places each authored comment, in ascending address order, as `//` lines directly
    /// above the FIRST line whose `sourceAddress` is exactly the commented address. Inserted lines have
    /// `source == nil`, so `lines(sourcedAt:)` and the GUI's unique-source-line rule are unchanged.
    /// A comment with no such line is reported in `unplacedComments`. With no comments the document is
    /// returned unchanged. `keepGoing` is called once per comment; returning false abandons the pass
    /// (the caller's cancellation then owns the result).
    static func applyingUserComments(
        _ comments: PseudocodeUserComments,
        to document: PseudocodeDocument,
        keepGoing: () -> Bool = { true }
    ) -> PseudocodeDocument {
        guard !comments.isEmpty else { return document }
        var firstLine: [UInt64: Int] = [:]
        for (index, line) in document.lines.enumerated() {
            if let address = line.sourceAddress, firstLine[address] == nil { firstLine[address] = index }
        }
        var insertions: [Int: [[String]]] = [:]
        var unplaced: [PseudocodeUnplacedComment] = []
        var placed = 0
        for address in comments.textByAddress.keys.sorted() {
            guard keepGoing() else { return document }
            guard let text = comments.textByAddress[address],
                  !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { continue }
            if let index = firstLine[address] {
                insertions[index, default: []].append(userCommentSegments(text))
                placed += 1
            } else {
                let reason: PseudocodeUnplacedCommentReason
                if comments.excludedAddresses.contains(address) {
                    reason = .excludedFromCode
                } else if comments.bodyAddresses.contains(address) {
                    reason = .folded
                } else {
                    reason = .noInstruction
                }
                unplaced.append(PseudocodeUnplacedComment(address: address, text: text, reason: reason))
            }
        }
        var result = document
        result.unplacedComments = unplaced
        result.placedCommentCount = placed
        guard !insertions.isEmpty else { return result }

        var lines: [PseudocodeLine] = []
        lines.reserveCapacity(document.lines.count + insertions.values.reduce(0) { $0 + $1.reduce(0) { $0 + $1.count } })
        // Old 1-based line number -> new 1-based line number of the SAME line.
        var newNumber: [Int: Int] = [:]
        for (index, line) in document.lines.enumerated() {
            if let groups = insertions[index] {
                let indent = String(line.text.prefix { $0 == " " || $0 == "\t" })
                for group in groups {
                    for segment in group {
                        let text = segment.isEmpty ? "\(indent)//" : "\(indent)// \(segment)"
                        let number = lines.count + 1
                        let width = Array(text).count
                        lines.append(PseudocodeLine(
                            lineNumber: number,
                            kind: .metadata,
                            text: text,
                            source: nil,
                            tokens: [PseudocodeToken(
                                lineNumber: number, kind: .comment,
                                text: String(Array(text)[indent.count..<width]),
                                range: indent.count..<width, sourceAddress: nil)]
                        ))
                    }
                }
            }
            var copy = line
            copy.lineNumber = lines.count + 1
            copy.tokens = line.tokens.map { token in
                var moved = token
                moved.lineNumber = copy.lineNumber
                return moved
            }
            newNumber[line.lineNumber] = copy.lineNumber
            lines.append(copy)
        }
        let delta = lines.count - document.lines.count
        func remapLine(_ number: Int) -> Int { newNumber[number] ?? (number + delta) }
        func remapNode(_ node: PseudocodeRegionNode) -> PseudocodeRegionNode {
            PseudocodeRegionNode(
                kind: node.kind,
                startLine: remapLine(node.startLine),
                endLine: remapLine(node.endLine),
                condition: node.condition,
                conditionSourceAddress: node.conditionSourceAddress,
                children: node.children.map { remapNode($0) }
            )
        }
        result.lines = lines
        result.regionTree = document.regionTree.map { remapNode($0) }
        return result
    }
}
