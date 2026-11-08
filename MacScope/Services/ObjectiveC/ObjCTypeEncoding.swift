import Foundation

/// Decodes Objective-C runtime type encodings into readable C/Objective-C type text, and
/// renders method signatures. A best-effort, CORRECTNESS-OVER-COVERAGE decoder: anything it
/// cannot decode becomes `id` (or `void` for an anonymous struct) rather than a guessed,
/// possibly-wrong type. The encoding grammar is the one in the Objective-C runtime (`@encode`).
enum ObjCTypeEncoding {

    /// Decodes a SINGLE leading type token of `encoding` (e.g. `@"NSString"` → `NSString *`,
    /// `^i` → `int *`, `{CGRect=…}` → `CGRect`, `r*` → `const char *`). Unknown/empty → `id`.
    static func decode(_ encoding: String) -> String {
        guard var context = ParseContext(encoding) else { return "id" }
        return decodeType(&context, depth: 0) ?? "id"
    }

    /// Renders a full method declaration, e.g. `- (id)initWithFrame:(CGRect)arg0;`. Argument
    /// names are positional (`arg0`, `arg1`, …) since the encoding carries no parameter names.
    static func methodSignature(_ method: ObjCMethod) -> String {
        let prefix = method.isClassMethod ? "+" : "-"
        let argCount = method.selector.filter { $0 == ":" }.count

        var returnType = "id"
        var argTypes = [String](repeating: "id", count: argCount)
        if let encoding = method.typeEncoding {
            let types = decodedTypes(of: encoding)
            if let first = types.first { returnType = first }
            // types[0] = return, types[1] = self (@), types[2] = SEL (:), types[3...] = args.
            let parsed = Array(types.dropFirst(3))
            for index in 0..<argCount where index < parsed.count { argTypes[index] = parsed[index] }
        }
        return "\(prefix) \(methodBody(returnType: returnType, selector: method.selector, argTypes: argTypes));"
    }

    /// Renders `Type name` with the pointer star hugging the name (`NSString *_title`, `int x`).
    static func declaration(type: String, name: String) -> String {
        let split = splitTrailingArraySubscripts(type)
        let declarator = split.base.hasSuffix("*") ? "\(split.base)\(name)" : "\(split.base) \(name)"
        return declarator + split.subscripts
    }

    // MARK: - Internals

    private static func methodBody(returnType: String, selector: String, argTypes: [String]) -> String {
        let returnPart = "(\(returnType))"
        guard selector.contains(":") else { return "\(returnPart)\(selector)" }
        // "foo:bar:" → keywords ["foo", "bar"] (the trailing "" component is dropped by the count guard).
        let parts = selector.components(separatedBy: ":")
        var pieces: [String] = []
        for index in 0..<argTypes.count where index < parts.count {
            pieces.append("\(parts[index]):(\(argTypes[index]))arg\(index)")
        }
        return returnPart + pieces.joined(separator: " ")
    }

    // All parser limits are local presentation limits, not claims about runtime ABI legality.
    private struct ParseContext {
        static let inputLimit = 8_192
        static let depthLimit = 32
        static let tokenLimit = 128
        static let workLimit = 16_384
        static let outputLimit = 8_192
        let bytes: [UInt8]
        var index = 0
        var work = 0
        var output = 0
        var tokens = 0

        init?(_ text: String) {
            var bounded: [UInt8] = []
            for byte in text.utf8 {
                guard bounded.count < Self.inputLimit else { return nil }
                bounded.append(byte)
            }
            bytes = bounded
        }

        var next: UInt8? { index < bytes.count ? bytes[index] : nil }

        mutating func charge(_ count: Int = 1) -> Bool {
            guard count >= 0, count <= Self.workLimit - work else { return false }
            work += count
            return true
        }

        mutating func take() -> UInt8? {
            guard let byte = next, charge() else { return nil }
            index += 1
            return byte
        }

        mutating func rendered(_ parts: [String]) -> String? {
            var length = 0
            for part in parts {
                let count = part.utf8.count // All parts originate in bounded input/results.
                guard count <= Self.outputLimit - length else { return nil }
                length += count
            }
            guard length <= Self.outputLimit - output, charge(length) else { return nil }
            output += length
            return parts.joined()
        }

        // Zero and leading zeros are retained exactly; at most 20 digits and UInt64 range.
        mutating func number() -> String? {
            let start = index
            var value: UInt64 = 0
            while let byte = next, ObjCTypeEncoding.isDigit(byte) {
                guard index - start < 20 else { return nil }
                let digit = UInt64(byte - 48)
                guard value <= (UInt64.max - digit) / 10, take() != nil else { return nil }
                value = value * 10 + digit
            }
            guard index > start else { return nil }
            return String(decoding: bytes[start..<index], as: UTF8.self)
        }

        mutating func quoted() -> String? {
            guard take() == 34 else { return nil }
            let start = index
            while let byte = next {
                if byte == 34 {
                    let end = index
                    guard take() != nil else { return nil }
                    return String(decoding: bytes[start..<end], as: UTF8.self)
                }
                // Escaped bytes do not close quotes or affect delimiter nesting.
                guard take() != nil else { return nil }
                if byte == 92 { guard take() != nil else { return nil } }
            }
            return nil
        }
    }

    private static func isDigit(_ byte: UInt8) -> Bool { byte >= 48 && byte <= 57 }

    /// Retain completed tokens, but stop at the first malformed token/offset: no resynchronization.
    private static func decodedTypes(of encoding: String) -> [String] {
        guard var context = ParseContext(encoding) else { return [] }
        var result: [String] = []
        while context.next != nil, context.tokens < ParseContext.tokenLimit {
            guard let decoded = decodeType(&context, depth: 0) else { break }
            context.tokens += 1
            result.append(decoded)
            if let byte = context.next, isDigit(byte), context.number() == nil { break }
        }
        return result
    }

    /// nil is failure; valid @, @? and @"" deliberately produce the non-nil string "id".
    private static func decodeType(_ context: inout ParseContext, depth: Int) -> String? {
        guard depth < ParseContext.depthLimit, context.charge() else { return nil }
        var isConst = false
        while let byte = context.next, [114, 110, 78, 111, 79, 82, 86].contains(byte) {
            if byte == 114 { isConst = true }
            guard context.take() != nil else { return nil }
        }
        guard let byte = context.take() else { return nil }
        let base: String
        switch byte {
        case 118: base = "void"
        case 99: base = "char"
        case 67: base = "unsigned char"
        case 115: base = "short"
        case 83: base = "unsigned short"
        case 105: base = "int"
        case 73: base = "unsigned int"
        case 108: base = "long"
        case 76: base = "unsigned long"
        case 113: base = "long long"
        case 81: base = "unsigned long long"
        case 102: base = "float"
        case 100: base = "double"
        case 68: base = "long double"
        case 66: base = "BOOL"
        case 42: base = "char *"
        case 35: base = "Class"
        case 58: base = "SEL"
        case 64:
            if context.next == 34 {
                guard let name = context.quoted() else { return nil }
                guard let text = context.rendered(name.isEmpty ? ["id"] : [name, " *"]) else { return nil }
                base = text
            } else {
                if context.next == 63 { guard context.take() != nil else { return nil } }
                base = "id"
            }
        case 94:
            guard let child = decodeType(&context, depth: depth + 1),
                  let text = context.rendered([child, child.hasSuffix("*") ? "*" : " *"]) else { return nil }
            base = text
        case 123, 40:
            guard let text = decodeAggregate(&context, opening: byte, depth: depth) else { return nil }
            base = text
        case 91:
            guard let extent = context.number(),
                  let element = decodeType(&context, depth: depth + 1),
                  context.take() == 93,
                  let split = splitArraySubscripts(element, context: &context),
                  let text = context.rendered([split.base, "[", extent, "]", split.subscripts]) else { return nil }
            base = text
        case 98:
            guard context.number() != nil else { return nil }
            base = "unsigned int"
        default: return nil
        }
        return context.rendered(isConst ? ["const ", base] : [base])
    }

    /// Name-only presentation, with structurally matched mixed delimiters and quoted fields.
    private static func decodeAggregate(_ context: inout ParseContext, opening: UInt8, depth: Int) -> String? {
        let start = context.index
        let closing: UInt8 = opening == 123 ? 125 : 41
        while let byte = context.next, byte != 61, byte != closing {
            guard ![123, 125, 40, 41, 91, 93, 34].contains(byte), context.take() != nil else { return nil }
        }
        let name = String(decoding: context.bytes[start..<context.index], as: UTF8.self)
        guard let separator = context.take() else { return nil }
        if separator == closing { return name.isEmpty || name == "?" ? "void" : name }
        guard separator == 61 else { return nil }
        var closings: [UInt8] = [closing]
        while let byte = context.next {
            if byte == 34 {
                guard context.quoted() != nil else { return nil }
                continue
            }
            guard context.take() != nil else { return nil }
            switch byte {
            case 123, 40, 91:
                guard closings.count < ParseContext.depthLimit - depth else { return nil }
                closings.append(byte == 123 ? 125 : (byte == 40 ? 41 : 93))
            case 125, 41, 93:
                guard closings.last == byte else { return nil }
                closings.removeLast()
                if closings.isEmpty { return name.isEmpty || name == "?" ? "void" : name }
            default: break
            }
        }
        return nil
    }

    private static func splitArraySubscripts(_ type: String, context: inout ParseContext) -> (base: String, subscripts: String)? {
        guard let bounded = ParseContext(type), context.charge(bounded.bytes.count) else { return nil }
        let bytes = bounded.bytes
        var end = bytes.count
        var suffixStart = end
        while end > 0, bytes[end - 1] == 93 {
            var cursor = end - 1
            let digitEnd = cursor
            while cursor > 0, isDigit(bytes[cursor - 1]) {
                guard context.charge() else { return nil }
                cursor -= 1
            }
            guard cursor > 0, bytes[cursor - 1] == 91, cursor < digitEnd else { break }
            suffixStart = cursor - 1
            end = suffixStart
        }
        return (String(decoding: bytes[..<suffixStart], as: UTF8.self),
                String(decoding: bytes[suffixStart...], as: UTF8.self))
    }

    private static func splitTrailingArraySubscripts(_ type: String) -> (base: String, subscripts: String) {
        guard var context = ParseContext(type), let split = splitArraySubscripts(type, context: &context) else {
            return ("id", "")
        }
        return split
    }
}
