// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

/// Detects duplicate object keys before Foundation decoding, including escaped-equivalent names.
/// It does not replace Foundation's value/type validation. Bounds apply before recursive parsing.
enum VAStrictJSON {
    static func validate(_ data: Data) throws {
        guard data.count <= 16 * 1024 * 1024 else { throw VAVerificationError.budgetExceeded("JSON input bytes") }
        var parser = Parser(bytes: Array(data))
        try parser.value(depth: 0)
        parser.whitespace()
        guard parser.index == parser.bytes.count else { throw VAVerificationError.invalidState("trailing JSON content") }
    }
    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        var tokens = 0
        mutating func whitespace() {
            while index < bytes.count && [UInt8(9), 10, 13, 32].contains(bytes[index]) { index += 1 }
        }
        mutating func consume(_ byte: UInt8) throws {
            whitespace()
            guard index < bytes.count, bytes[index] == byte else {
                throw VAVerificationError.invalidState("invalid JSON structure")
            }
            index += 1
        }
        mutating func value(depth: Int) throws {
            guard depth <= 64, tokens < 1_000_000 else { throw VAVerificationError.budgetExceeded("JSON nesting or token count") }
            tokens += 1
            whitespace()
            guard index < bytes.count else { throw VAVerificationError.invalidState("missing JSON value") }
            switch bytes[index] {
            case 123: // object
                index += 1
                whitespace()
                if index < bytes.count && bytes[index] == 125 { index += 1; return }
                var keys = Set<String>()
                while true {
                    whitespace()
                    let range = try string()
                    // Foundation validates escapes, UTF-8 and Unicode surrogate pairs for the key.
                    let key = try JSONDecoder().decode(String.self, from: Data(bytes[range]))
                    guard keys.insert(key).inserted else { throw VAVerificationError.invalidState("duplicate JSON object key") }
                    try consume(58)
                    try value(depth: depth + 1)
                    whitespace()
                    guard index < bytes.count else { throw VAVerificationError.invalidState("unterminated JSON object") }
                    if bytes[index] == 125 { index += 1; return }
                    try consume(44)
                }
            case 91: // array
                index += 1
                whitespace()
                if index < bytes.count && bytes[index] == 93 { index += 1; return }
                while true {
                    try value(depth: depth + 1)
                    whitespace()
                    guard index < bytes.count else { throw VAVerificationError.invalidState("unterminated JSON array") }
                    if bytes[index] == 93 { index += 1; return }
                    try consume(44)
                }
            case 34: _ = try string()
            default:
                let start = index
                while index < bytes.count && ![UInt8(9), 10, 13, 32, 44, 93, 125].contains(bytes[index]) {
                    index += 1
                }
                guard index > start else { throw VAVerificationError.invalidState("missing JSON scalar") }
                // JSONDecoder performs the final number/literal grammar and requested-type check.
            }
        }
        mutating func string() throws -> Range<Int> {
            let start = index
            guard index < bytes.count, bytes[index] == 34 else { throw VAVerificationError.invalidState("expected JSON string") }
            index += 1
            while index < bytes.count {
                let byte = bytes[index]
                if byte == 34 { index += 1; return start..<index }
                guard byte >= 32 else { throw VAVerificationError.invalidState("control byte in JSON string") }
                if byte == 92 {
                    index += 1
                    guard index < bytes.count else { throw VAVerificationError.invalidState("truncated JSON escape") }
                    let escape = bytes[index]
                    if escape == 117 {
                        guard index + 4 < bytes.count else { throw VAVerificationError.invalidState("truncated Unicode escape") }
                        for position in (index + 1)...(index + 4) {
                            let digit = bytes[position]
                            guard (48...57).contains(digit) || (65...70).contains(digit) || (97...102).contains(digit) else {
                                throw VAVerificationError.invalidState("invalid Unicode escape")
                            }
                        }
                        index += 4
                    } else if ![UInt8(34), 92, 47, 98, 102, 110, 114, 116].contains(escape) {
                        throw VAVerificationError.invalidState("invalid JSON escape")
                    }
                }
                index += 1
            }
            throw VAVerificationError.invalidState("unterminated JSON string")
        }
    }
}
