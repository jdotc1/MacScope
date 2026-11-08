import Foundation

/// Limits work admitted by filtered symbol selection, including nonmatching rows.
enum SymbolFilterSelection {
    static func indices(_ symbols: [SymbolSummary],
                        matching: (String, String, String?) -> Bool,
                        checkpoint: () throws -> Void) throws -> [Int] {
        var visits = 0
        var bytes = 0
        func refusal(_ detail: String, _ unit: MCPRefusalBudget.Unit, _ limit: Int, _ used: Int) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: "symbols filter \(detail)",
                budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used), narrowing: []))
        }
        func admit(_ value: String) throws {
            try checkpoint()
            let view = value.utf8
            var cursor = view.startIndex
            var fieldBytes = 0
            while cursor != view.endIndex {
                guard fieldBytes < 4_096 else { throw refusal("field exceeds the UTF-8 admission limit", .bytes, 4_096, fieldBytes) }
                guard bytes < 1_048_576 else { throw refusal("requires another UTF-8 admission byte", .bytes, 1_048_576, bytes) }
                _ = view[cursor]
                view.formIndex(after: &cursor)
                fieldBytes += 1
                bytes += 1
                if fieldBytes.isMultiple(of: 256) { try checkpoint() }
            }
            try checkpoint()
        }
        var result: [Int] = []
        for index in symbols.indices {
            try checkpoint()
            guard visits < 100_000 else { throw refusal("requires another candidate visit", .workSteps, 100_000, visits) }
            visits += 1
            let symbol = symbols[index]
            try admit(symbol.name)
            try admit(symbol.kind)
            try checkpoint()
            if matching(symbol.name, symbol.name, symbol.kind) { result.append(index) }
        }
        try checkpoint()
        return result
    }
}

/// Holds admitted source offsets and display names so paging never rescans names.
enum FunctionFilterSelection {
    struct Entry {
        let offset: Int
        let function: FunctionSummary
        let displayName: String
    }

    static func select(_ snapshot: WorkspaceSnapshot, matching: (String, String, String?) -> Bool,
                       checkpoint: () throws -> Void) throws -> [Entry] {
        var visits = 0, bytes = 0
        func refusal(_ detail: String, _ unit: MCPRefusalBudget.Unit, _ limit: Int, _ used: Int) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: "functions filter \(detail)",
                budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used), narrowing: []))
        }
        func visit() throws {
            try checkpoint()
            guard visits < 100_000 else { throw refusal("requires another function or override visit", .workSteps, 100_000, visits) }
            visits += 1
        }
        func admit(_ text: String) throws {
            try checkpoint()
            let utf8 = text.utf8
            var position = utf8.startIndex, fieldBytes = 0
            while position != utf8.endIndex {
                guard fieldBytes < 4_096 else { throw refusal("name exceeds the UTF-8 admission limit", .bytes, 4_096, fieldBytes) }
                guard bytes < 1_048_576 else { throw refusal("requires another UTF-8 admission byte", .bytes, 1_048_576, bytes) }
                utf8.formIndex(after: &position)
                fieldBytes += 1; bytes += 1
                if fieldBytes.isMultiple(of: 256) { try checkpoint() }
            }
            try checkpoint()
        }
        var selected: [Entry] = []
        for (offset, function) in snapshot.functions.enumerated() {
            try visit(); try admit(function.name); try visit()
            let name = snapshot.displayName(at: function.startAddress, default: function.name)
            try admit(name); try checkpoint()
            if matching(name, function.name, nil) { selected.append(Entry(offset: offset, function: function, displayName: name)) }
        }
        try checkpoint()
        return selected
    }
}

struct ListRowFilter: Equatable, Sendable {
    let nameContains: String?
    let regex: String?
    let kind: String?

    static let maximumListRegexBytes = 256
    static let allowedSymbolKinds = [
        "local", "import", "export", "undefined", "absolute", "indirect", "stub", "library-signature", "objc-method",
    ]

    var isEmpty: Bool { nameContains == nil && regex == nil && kind == nil }

    static func parse(_ arguments: ScriptValue, command: String) throws -> ListRowFilter {
        func text(_ key: String, maximum: Int = 1_024) throws -> String? {
            guard let value = arguments[key] else { return nil }
            guard case .string(let string) = value, !string.isEmpty,
                  string.utf8.prefix(maximum + 1).count <= maximum else {
                throw ScriptingError.invalidArgument(
                    "\(key) must be a non-empty string of at most \(maximum) UTF-8 bytes")
            }
            return string
        }
        let contains = try text("nameContains")
        let pattern = try text("regex", maximum: maximumListRegexBytes)
        let kind: String?
        if command == "symbols" { kind = try text("kind") }
        else { kind = nil }
        if let kind, !allowedSymbolKinds.contains(kind) {
            throw ScriptingError.invalidArgument("kind must be one of " + allowedSymbolKinds.joined(separator: "|"))
        }
        if let pattern {
            do { _ = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) }
            catch { throw ScriptingError.invalidArgument("regex is not a valid regular expression") }
        }
        return ListRowFilter(nameContains: contains, regex: pattern, kind: kind)
    }

    func matcher() throws -> (_ name: String, _ rawName: String, _ kind: String?) -> Bool {
        let expression: NSRegularExpression?
        if let regex {
            do { expression = try NSRegularExpression(pattern: regex, options: [.caseInsensitive]) }
            catch { throw ScriptingError.invalidArgument("regex is not a valid regular expression") }
        } else { expression = nil }
        let locale = Locale(identifier: "en_US_POSIX")
        let selectedKind = kind
        let contains = nameContains
        return { name, rawName, rowKind in
            if let kind = selectedKind, rowKind != kind { return false }
            if let nameContains = contains {
                let found = name.range(of: nameContains, options: [.caseInsensitive, .literal], locale: locale) != nil
                    || rawName.range(of: nameContains, options: [.caseInsensitive, .literal], locale: locale) != nil
                if !found { return false }
            }
            if let expression {
                let found = expression.firstMatch(in: name, options: [], range: NSRange(name.startIndex..<name.endIndex, in: name)) != nil
                    || expression.firstMatch(in: rawName, options: [], range: NSRange(rawName.startIndex..<rawName.endIndex, in: rawName)) != nil
                if !found { return false }
            }
            return true
        }
    }

    var digest: String {
        func tagged(_ value: String?) -> String {
            guard let value else { return "0" }
            let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\0", with: "\\0")
            return "1" + escaped
        }
        let folded = nameContains?.folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        let text = "n=\(tagged(folded))\0r=\(tagged(regex))\0k=\(tagged(kind))"
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in text.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
        let hex = String(hash, radix: 16)
        return String(repeating: "0", count: 16 - hex.count) + hex
    }

    /// Page-only context cap; matching and legacy rows retain the full kind value.
    static func pageKind(_ text: String, checkpoint: () throws -> Void) throws
        -> (text: String, byteLength: Int, truncated: Bool) {
        let count = text.utf8.count
        guard count > 1_024 else { return (text, count, false) }
        var prefix = ""
        var used = 0
        for (index, scalar) in text.unicodeScalars.enumerated() {
            if index % 256 == 0 { try checkpoint() }
            let width: Int
            switch scalar.value {
            case 0...0x7f: width = 1
            case 0x80...0x7ff: width = 2
            case 0x800...0xffff: width = 3
            default: width = 4
            }
            guard used + width <= 1_024 else { break }
            prefix.unicodeScalars.append(scalar)
            used += width
        }
        return (prefix, count, true)
    }
}
