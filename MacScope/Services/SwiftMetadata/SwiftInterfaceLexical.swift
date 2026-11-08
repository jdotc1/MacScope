import Foundation

/// Display-only conservative subset, never an identity or type-resolution authority.
enum SwiftInterfaceLexical {
    private static let keywords: Set<String> = [
        "associatedtype", "borrowing", "class", "consuming", "deinit", "enum", "extension",
        "fileprivate", "func", "import", "init", "inout", "internal", "let", "nonisolated",
        "open", "operator", "precedencegroup", "private", "protocol", "public", "rethrows",
        "static", "struct", "subscript", "typealias", "var", "break", "case", "catch",
        "continue", "default", "defer", "do", "else", "fallthrough", "for", "guard", "if",
        "in", "repeat", "return", "switch", "throw", "where", "while", "Any", "as", "await",
        "false", "is", "nil", "self", "Self", "super", "throws", "true", "try", "Type", "Protocol"
    ]

    // A deliberately narrow subset of the supplied Swift Book identifier-head ranges.
    // Unicode letters in Latin/Greek/Cyrillic/CJK/kana ranges, not arbitrary Unicode categories.
    private static func head(_ scalar: Unicode.Scalar) -> Bool {
        let v = scalar.value
        if v == 95 || (65...90).contains(v) || (97...122).contains(v) { return true }
        let supported = (0xC0...0xD6).contains(v) || (0xD8...0xF6).contains(v)
            || (0xF8...0x2FF).contains(v) || (0x370...0x52F).contains(v)
            || (0x3041...0x3096).contains(v) || (0x30A1...0x30FA).contains(v)
            || (0x4E00...0x9FFF).contains(v)
        return supported && CharacterSet.letters.contains(scalar)
    }
    private static func tail(_ scalar: Unicode.Scalar) -> Bool {
        head(scalar) || (48...57).contains(scalar.value) || (0x300...0x36F).contains(scalar.value)
    }
    static func identifier(_ text: String) -> String? {
        guard text != "_", let first = text.unicodeScalars.first, head(first),
              text.unicodeScalars.dropFirst().allSatisfy(tail) else { return nil }
        return keywords.contains(text) ? "`\(text)`" : text
    }
    /// Called only after the renderer's original isSourcePath admission, not on single names.
    static func path(_ text: String) -> String? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        var result: [String] = []
        for part in parts {
            guard let name = identifier(String(part)) else { return nil }
            result.append(name)
        }
        return result.isEmpty ? nil : result.joined(separator: ".")
    }
    /// Reversible scalar escapes. Backslash is escaped too, so literal escape-looking text differs.
    static func comment(_ text: String) -> String {
        var result = ""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 0...31, 127...159, 0x2028, 0x2029, 34, 39, 47, 92, 96,
                 0x200B...0x200F, 0x202A...0x202E, 0x2060...0x206F:
                result += "\\u{\(String(scalar.value, radix: 16))}"
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result
    }

    /// Recognizes only a small safe display subset; returns the ORIGINAL display, not a new type.
    /// Nominal paths/generics, unlabeled tuples, arrays/dictionaries and optional suffixes.
    /// No functions, attributes, raw identifiers, ownership syntax or mangling interpretation.
    static func typeDisplay(_ text: String) -> String? {
        guard text.utf8.count <= 4096 else { return nil }
        var reader = DisplayReader(scalars: Array(text.unicodeScalars))
        guard reader.type(depth: 0) else { return nil }
        reader.spaces()
        return reader.index == reader.scalars.count ? text : nil
    }
    private struct DisplayReader {
        let scalars: [Unicode.Scalar]
        var index = 0
        mutating func spaces() { while index < scalars.count && scalars[index] == " " { index += 1 } }
        mutating func take(_ scalar: Unicode.Scalar) -> Bool {
            spaces()
            guard index < scalars.count && scalars[index] == scalar else { return false }
            index += 1; return true
        }
        mutating func word() -> Bool {
            spaces()
            let start = index
            guard index < scalars.count, head(scalars[index]) else { return false }
            index += 1
            while index < scalars.count && tail(scalars[index]) { index += 1 }
            let text = String(String.UnicodeScalarView(scalars[start..<index]))
            return text != "_" && (!keywords.contains(text) || text == "Any" || text == "Self")
        }
        mutating func type(depth: Int) -> Bool {
            guard depth < 32 else { return false }
            if take("[") {
                guard type(depth: depth + 1) else { return false }
                if take(":") { guard type(depth: depth + 1) else { return false } }
                guard take("]") else { return false }
            } else if take("(") {
                if !take(")") {
                    guard type(depth: depth + 1) else { return false }
                    while take(",") { guard type(depth: depth + 1) else { return false } }
                    guard take(")") else { return false }
                }
            } else {
                guard word() else { return false }
                while take(".") { guard word() else { return false } }
                if take("<") {
                    guard type(depth: depth + 1) else { return false }
                    while take(",") { guard type(depth: depth + 1) else { return false } }
                    guard take(">") else { return false }
                }
            }
            while take("?") || take("!") {}
            return true
        }
    }
}
