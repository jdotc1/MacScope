import Foundation

struct SwiftBroadParseLimits {
    var maxSymbolLength = 4096, maxIdentifierLength = 256, maxContextDepth = 16
    var maxNodes = 256, maxSubstitutions = 128, maxParameters = 64
    var maxTypeDepth = 16, maxGenericParameters = 32
}
struct SwiftBroadContext: Equatable {
    let name: String, kind: String
    var json: SwiftOutcomeJSON { .object(["name": .string(name), "kind": .string(kind)]) }
}
final class SwiftBroadType: Equatable {
    let name: String
    let arguments: [SwiftBroadType]
    let `inout`: Bool
    var isInout: Bool { self.inout }
    let label: String?
    let genericDepth: Int?, genericIndex: Int?, nominalKind: String?
    fileprivate let depth: Int
    init(_ name: String, arguments: [SwiftBroadType] = [], isInout: Bool = false,
         label: String? = nil, genericDepth: Int? = nil, genericIndex: Int? = nil,
         nominalKind: String? = nil, depth: Int = 1) {
        self.name = name; self.arguments = arguments; self.inout = isInout; self.label = label
        self.genericDepth = genericDepth; self.genericIndex = genericIndex; self.nominalKind = nominalKind; self.depth = depth
    }
    var json: SwiftOutcomeJSON { .object([
        "name": .string(name), "arguments": .array(arguments.map(\.json)), "inout": .bool(self.inout),
        "label": label.map(SwiftOutcomeJSON.string) ?? .null,
        "generic_depth": genericDepth.map { .integer(Int128($0)) } ?? .null,
        "generic_index": genericIndex.map { .integer(Int128($0)) } ?? .null,
        "nominal_kind": nominalKind.map(SwiftOutcomeJSON.string) ?? .null]) }
    static func == (lhs: SwiftBroadType, rhs: SwiftBroadType) -> Bool { lhs.json == rhs.json }
    fileprivate func annotated(isInout: Bool, label: String?) -> SwiftBroadType {
        SwiftBroadType(name, arguments: arguments, isInout: isInout, label: label,
                       genericDepth: genericDepth, genericIndex: genericIndex, nominalKind: nominalKind, depth: depth)
    }
}
struct SwiftBroadGenericRequirement: Equatable {
    let `protocol`: String
    let parameterDepth: Int, parameterIndex: Int
    var json: SwiftOutcomeJSON { .object(["protocol": .string(self.protocol),
        "parameter_depth": .integer(Int128(parameterDepth)), "parameter_index": .integer(Int128(parameterIndex))]) }
}
struct SwiftBroadGenericBinding: Equatable {
    let parameterDepth: Int, parameterIndex: Int
    let replacement: SwiftBroadType
    var json: SwiftOutcomeJSON { .object(["parameter_depth": .integer(Int128(parameterDepth)),
        "parameter_index": .integer(Int128(parameterIndex)), "replacement": replacement.json]) }
}
struct SwiftBroadSpecialization: Equatable {
    let templateSymbol: String, kind: String
    let passID: Int
    let serialized: Bool, asyncRemoved: Bool, representationChanged: Bool
    let droppedArgumentOrdinals: [Int]
    let bindings: [SwiftBroadGenericBinding]
    let substitutedParameterTypes: [SwiftBroadType]
    let substitutedResultType: SwiftBroadType
    var json: SwiftOutcomeJSON { .object([
        "template_symbol": .string(templateSymbol), "kind": .string(kind), "pass_id": .integer(Int128(passID)),
        "serialized": .bool(serialized), "async_removed": .bool(asyncRemoved), "representation_changed": .bool(representationChanged),
        "dropped_argument_ordinals": .array(droppedArgumentOrdinals.map { .integer(Int128($0)) }),
        "bindings": .array(bindings.map(\.json)), "substituted_parameter_types": .array(substitutedParameterTypes.map(\.json)),
        "substituted_result_type": substitutedResultType.json]) }
}
struct SwiftBroadCallableIdentity: Equatable {
    let symbol: String, module: String
    let context: [SwiftBroadContext]
    let callableKind: String, functionName: String
    let parameterLabels: [String?]
    let parameterTypes: [SwiftBroadType]
    let resultType: SwiftBroadType
    let `throws`: Bool
    var throwsFlag: Bool { self.throws }
    let genericParameterCounts: [Int]
    let genericRequirements: [SwiftBroadGenericRequirement]
    let originalCallableKind: String?
    let specialization: SwiftBroadSpecialization?
    let syntaxModel = "swift-broad-declaration-syntax-v1"
    init(symbol: String, module: String, context: [SwiftBroadContext], callableKind: String, functionName: String,
         parameterLabels: [String?], parameterTypes: [SwiftBroadType], resultType: SwiftBroadType,
         throwsFlag throwing: Bool, genericParameterCounts: [Int] = [], genericRequirements: [SwiftBroadGenericRequirement] = [],
         originalCallableKind: String? = nil, specialization: SwiftBroadSpecialization? = nil) {
        self.symbol = symbol; self.module = module; self.context = context; self.callableKind = callableKind
        self.functionName = functionName; self.parameterLabels = parameterLabels; self.parameterTypes = parameterTypes
        self.resultType = resultType; self.throws = throwing; self.genericParameterCounts = genericParameterCounts
        self.genericRequirements = genericRequirements; self.originalCallableKind = originalCallableKind; self.specialization = specialization
    }
    var json: SwiftOutcomeJSON { .object([
        "symbol": .string(symbol), "module": .string(module), "context": .array(context.map(\.json)),
        "callable_kind": .string(callableKind), "function_name": .string(functionName),
        "parameter_labels": .array(parameterLabels.map { $0.map(SwiftOutcomeJSON.string) ?? .null }),
        "parameter_types": .array(parameterTypes.map(\.json)), "result_type": resultType.json, "throws": .bool(self.throws),
        "generic_parameter_counts": .array(genericParameterCounts.map { .integer(Int128($0)) }),
        "generic_requirements": .array(genericRequirements.map(\.json)),
        "original_callable_kind": originalCallableKind.map(SwiftOutcomeJSON.string) ?? .null,
        "specialization": specialization?.json ?? .null, "syntax_model": .string(syntaxModel)]) }
}
struct SwiftBroadDeclarationResult {
    let identity: SwiftBroadCallableIdentity?
    let unsupportedReason: String?
    let detail: String
    let offset: Int
    var supported: Bool { identity != nil && unsupportedReason == nil }
    init(_ identity: SwiftBroadCallableIdentity?, _ reason: String? = nil, _ detail: String = "", _ offset: Int = 0) {
        self.identity = identity; self.unsupportedReason = reason; self.detail = detail; self.offset = offset
    }
}
private struct SwiftBroadDecline: Error { let reason: String, detail: String }
private enum SwiftBroadOperand {
    case empty, first, text(String), type(SwiftBroadType)
    var isTypeOrEmpty: Bool { switch self { case .empty, .type: return true; default: return false } }
    var isEmpty: Bool { if case .empty = self { return true }; return false }
    var isFirst: Bool { if case .first = self { return true }; return false }
}
private final class SwiftBroadParser {
    let original: String, text: [Character], limits: SwiftBroadParseLimits
    var pos = 2, nodes = 0
    var substitutions: [SwiftBroadOperand] = [], words: [String] = []
    let builtins = ["i": "Swift.Int", "u": "Swift.UInt", "b": "Swift.Bool", "f": "Swift.Float", "d": "Swift.Double", "S": "Swift.String"]
    let nominal = ["V": "struct", "O": "enum", "C": "class"]
    let integerNames: Set<String> = ["Int8", "Int16", "Int32", "Int64", "UInt8", "UInt16", "UInt32", "UInt64"]
    init(_ symbol: String, _ limits: SwiftBroadParseLimits) {
        original = symbol; text = Array(symbol.hasPrefix("_$s") ? String(symbol.dropFirst()) : symbol); self.limits = limits
    }
    func char(_ at: Int? = nil) -> String { let i = at ?? pos; return i >= 0 && i < text.count ? String(text[i]) : "" }
    var tail: String { String(text.dropFirst(pos)) }
    func decline(_ reason: String, _ detail: String) throws -> Never { throw SwiftBroadDecline(reason: reason, detail: detail) }
    func limit(_ condition: Bool, _ detail: String) throws { if condition { try decline("resource_limit", detail) } }
    func addSubstitution(_ value: SwiftBroadOperand) throws {
        try limit(substitutions.count >= limits.maxSubstitutions, "substitution table limit"); substitutions.append(value)
    }
    func match(_ pattern: String) -> String? {
        tail.range(of: "^(?:" + pattern + ")", options: .regularExpression).map { String(tail[$0]) }
    }
    func literalIdentifierPart(fragment: Bool = false) throws -> String {
        guard let digits = match("[1-9][0-9]*") else { try decline("invalid_grammar", "expected identifier literal length") }
        try limit(digits.count > 6, "identifier length digit limit")
        guard let size = Int(digits) else { try decline("resource_limit", "identifier length digit limit") }
        try limit(size > limits.maxIdentifierLength, "identifier length limit"); pos += digits.count
        let value = String(text.dropFirst(pos).prefix(size))
        let pattern = fragment ? "^[A-Za-z_0-9$]+$" : "^[A-Za-z_][A-Za-z_0-9$]*$"
        guard value.count == size, value.range(of: pattern, options: .regularExpression) != nil else {
            try decline("invalid_grammar", "invalid or truncated identifier literal")
        }
        pos += size
        let chars = Array(value); var begin: Int?
        for i in 0...chars.count {
            let c: Character? = i < chars.count ? chars[i] : nil
            if let start = begin, c == nil || c == "_" || (c!.isUppercase && !chars[i - 1].isUppercase) {
                let word = String(chars[start..<i]); if word.count >= 2 && words.count < 26 { words.append(word) }; begin = nil
            }
            if begin == nil, let c, !c.isNumber, c != "_" { begin = i }
        }
        return value
    }
    func identifier() throws -> String {
        if tail.hasPrefix("00") { try decline("unicode_identifier", "Punycode identifier encoding is not implemented") }
        let value: String
        if char() != "0" { value = try literalIdentifierPart() }
        else {
            pos += 1; var parts: [String] = []; var moreWords = true, terminated = false
            while pos < text.count {
                while moreWords && text.indices.contains(pos) && text[pos].isLetter {
                    let c = text[pos]; let index = Int(c.lowercased().utf8.first!) - 97
                    guard index >= 0 && index < words.count else { try decline("unknown_substitution", "word substitution index is absent") }
                    parts.append(words[index]); pos += 1
                    if c.isUppercase { moreWords = false }
                }
                if char() == "0" { pos += 1; terminated = true; break }
                parts.append(try literalIdentifierPart(fragment: true))
                try limit(parts.reduce(0) { $0 + $1.count } > limits.maxIdentifierLength, "expanded identifier length limit")
                if !moreWords { terminated = true; break }
            }
            if !terminated { try decline("invalid_grammar", "unterminated word-substituted identifier") }
            value = parts.joined()
            try limit(value.count > limits.maxIdentifierLength, "expanded identifier length limit")
            guard value.range(of: "^[A-Za-z_][A-Za-z_0-9$]*$", options: .regularExpression) != nil else { try decline("invalid_grammar", "invalid expanded identifier") }
        }
        try addSubstitution(.text(value)); return value
    }
    func popType(_ stack: inout [SwiftBroadOperand]) throws -> SwiftBroadType {
        guard let value = stack.popLast() else { try decline("invalid_grammar", "missing type operand") }
        switch value { case .empty: return SwiftBroadType("Swift.Void")
        case .type(let node): return node
        default: try decline("invalid_grammar", "non-type operand") }
    }
    func typeNode(_ name: String, _ arguments: [SwiftBroadType] = [], isInout: Bool = false,
                  label: String? = nil, genericDepth: Int? = nil, genericIndex: Int? = nil, nominalKind: String? = nil) throws -> SwiftBroadType {
        nodes += 1; try limit(nodes > limits.maxNodes, "AST node limit")
        let depth = 1 + (arguments.map(\.depth).max() ?? 0)
        try limit(depth > limits.maxTypeDepth, "type depth limit")
        return SwiftBroadType(name, arguments: arguments, isInout: isInout, label: label,
                              genericDepth: genericDepth, genericIndex: genericIndex, nominalKind: nominalKind, depth: depth)
    }
    func index() throws -> Int {
        if char() == "_" { pos += 1; return 0 }
        guard let number = match("[1-9][0-9]{0,5}_"), let value = Int(number.dropLast()) else { try decline("invalid_grammar", "invalid index") }
        pos += number.count; return value + 1
    }
    func specialization(_ template: SwiftBroadCallableIdentity) throws -> SwiftBroadCallableIdentity {
        let start = pos
        if tail.hasPrefix("T") { try decline("thunk_or_specialization", tail.hasPrefix("Tf") ? "function-signature specialization may change argument/return ABI" : "unsupported thunk or specialization production") }
        guard tail.hasPrefix("S") || tail.hasPrefix("s") else { try decline("unconsumed_suffix", "unconsumed declaration suffix") }
        var replacements: [SwiftBroadType] = [], markerSeen = false
        while pos < text.count && char() != "T" {
            if tail.hasPrefix("_") {
                guard !markerSeen && replacements.count == 1 else { try decline("invalid_grammar", "replacement type-list marker requires exactly one preceding type") }
                markerSeen = true; pos += 1; continue
            }
            if tail.hasPrefix("Sg") {
                guard !replacements.isEmpty && !(markerSeen && replacements.count == 1) else { try decline("invalid_grammar", "optional replacement lacks a type before its list delimiter") }
                pos += 2; replacements[replacements.count - 1] = try typeNode("Optional", [replacements.last!]); continue
            }
            if char() == "S", let builtin = builtins[char(pos + 1)] {
                replacements.append(try typeNode(builtin, nominalKind: "struct")); pos += 2
            } else if char() == "s" {
                pos += 1; let name = try identifier()
                guard integerNames.contains(name), char() == "V" else { try decline("thunk_or_specialization", "unsupported concrete replacement type") }
                pos += 1; replacements.append(try typeNode("Swift." + name, nominalKind: "struct"))
            } else { try decline("thunk_or_specialization", "unsupported specialization replacement grammar") }
            try limit(replacements.count > limits.maxGenericParameters, "specialization replacement count limit")
        }
        guard markerSeen, !replacements.isEmpty, char() == "T" else { try decline("invalid_grammar", "incomplete generic specialization type list") }
        pos += 1; var dropped: [Int] = []
        while char() == "t" {
            pos += 1; let ordinal: Int
            if let number = match("[1-9][0-9]*") {
                try limit(number.count > 6, "dropped argument ordinal digit limit")
                guard let n = Int(number) else { try decline("resource_limit", "dropped argument ordinal digit limit") }
                ordinal = n + 1; pos += number.count
            } else { ordinal = 0 }
            try limit(ordinal > limits.maxParameters || dropped.count >= limits.maxParameters, "dropped argument limit")
            guard !dropped.contains(ordinal) else { try decline("invalid_grammar", "duplicate dropped argument ordinal") }
            dropped.append(ordinal)
        }
        let kinds = ["g": "generic_reabstracted", "G": "generic_not_reabstracted", "B": "generic_resilient"]
        guard let kind = kinds[char()] else { try decline("thunk_or_specialization", "unsupported generic specialization kind") }
        pos += 1; var attributes: [Bool] = []
        for flag in ["q", "a", "r"] { let present = char() == flag; attributes.append(present); if present { pos += 1 } }
        guard char().count == 1, let pass = Int(char()), (0...9).contains(pass) else { try decline("invalid_grammar", "specialization requires a single known pass digit after ordered flags") }
        pos += 1
        guard pos == text.count else { try decline("unconsumed_suffix", "unconsumed specialization suffix") }
        guard template.genericParameterCounts.count == 1, template.genericParameterCounts[0] == replacements.count else {
            try decline("generic_requirements", "concrete replacement count does not match one supported generic environment")
        }
        let bindings = replacements.enumerated().map { SwiftBroadGenericBinding(parameterDepth: 0, parameterIndex: $0.offset, replacement: $0.element) }
        var memo: [ObjectIdentifier: SwiftBroadType] = [:]
        func substitute(_ root: SwiftBroadType) throws -> SwiftBroadType {
            var pending: [(SwiftBroadType, Bool)] = [(root, false)]
            while let (node, ready) = pending.popLast() {
                let id = ObjectIdentifier(node); if memo[id] != nil { continue }
                if node.genericDepth != nil {
                    guard let i = node.genericIndex, replacements.indices.contains(i) else { try decline("generic_requirements", "concrete replacement count does not match one supported generic environment") }
                    var replacement = replacements[i]
                    if node.inout || node.label != nil { replacement = replacement.annotated(isInout: node.inout, label: node.label) }
                    memo[id] = replacement
                } else if ready {
                    let args = node.arguments.map { memo[ObjectIdentifier($0)]! }
                    memo[id] = try typeNode(node.name, args, isInout: node.inout, label: node.label, nominalKind: node.nominalKind)
                } else {
                    pending.append((node, true)); pending.append(contentsOf: node.arguments.map { ($0, false) })
                }
            }
            return memo[ObjectIdentifier(root)]!
        }
        let parameters = try template.parameterTypes.map { try substitute($0) }
        let result = try substitute(template.resultType)
        let spec = SwiftBroadSpecialization(templateSymbol: String(original.prefix(start + (original.hasPrefix("_$s") ? 1 : 0))),
            kind: kind, passID: pass, serialized: attributes[0], asyncRemoved: attributes[1], representationChanged: attributes[2],
            droppedArgumentOrdinals: dropped, bindings: bindings, substitutedParameterTypes: parameters, substitutedResultType: result)
        return SwiftBroadCallableIdentity(symbol: template.symbol, module: template.module, context: template.context,
            callableKind: "generic_specialization", functionName: template.functionName, parameterLabels: template.parameterLabels,
            parameterTypes: template.parameterTypes, resultType: template.resultType, throwsFlag: template.throws,
            genericParameterCounts: template.genericParameterCounts, genericRequirements: template.genericRequirements,
            originalCallableKind: template.callableKind, specialization: spec)
    }
    func parse() throws -> SwiftBroadCallableIdentity {
        let module = try identifier(); var context: [SwiftBroadContext] = []; var function = ""
        while true {
            let name = try identifier(), code = char()
            if code == "P" { try decline("protocol_context", "protocol declaration/requirement needs separate qualification") }
            guard let kind = nominal[code] else { function = name; break }
            pos += 1; context.append(SwiftBroadContext(name: name, kind: kind))
            try limit(context.count > limits.maxContextDepth, "context nesting limit")
            try addSubstitution(.type(typeNode(([module] + context.map(\.name)).joined(separator: "."), nominalKind: kind)))
        }
        var stack: [SwiftBroadOperand] = [], throwing = false, genericCounts: [Int] = [], requirements: [SwiftBroadGenericRequirement] = []
        while pos < text.count {
            try limit(stack.count > limits.maxNodes, "operand stack limit")
            let code = char()
            if (throwing || !genericCounts.isEmpty) && !["F", "l", "r"].contains(code) {
                if !["T", "Y", "c", "X", "R"].contains(code) && !tail.hasPrefix("Sz") { try decline("invalid_grammar", "operand after signature annotation") }
            }
            if ["K", "l", "r"].contains(code), stack.count < 2 || !stack.suffix(2).allSatisfy(\.isTypeOrEmpty) {
                try decline("invalid_grammar", "signature annotation lacks result/parameters")
            }
            if ["Ya", "Yb", "Yc", "YA", "YC", "YT"].contains(where: { tail.hasPrefix($0) }) { try decline("async_context", "async/isolation/sendability annotation requires separate qualification") }
            if tail.hasPrefix("YK") { try decline("typed_throws", "typed throws annotation requires separate qualification") }
            if tail.hasPrefix("XE") || tail.hasPrefix("XK") || code == "c" { try decline("closure_type", "function/closure parameter type requires separate qualification; rethrows cannot be inferred") }
            if code == "T" { try decline("thunk_or_specialization", "thunk or specialization requires separate qualification") }
            if text[pos].isNumber { stack.append(.text(try identifier())); continue }
            pos += 1
            switch code {
            case "y": stack.append(.empty)
            case "_": stack.append(.first)
            case "K":
                if throwing { try decline("invalid_grammar", "duplicate throws annotation") }; throwing = true
            case "S":
                if char() == "g" {
                    pos += 1; let node = try typeNode("Optional", [popType(&stack)])
                    try addSubstitution(.type(node)); stack.append(.type(node)); continue
                }
                var count = 1
                if let number = match("[1-9][0-9]{0,5}") { count = Int(number)!; pos += number.count }
                try limit(count > limits.maxNodes, "repeat substitution limit")
                let kind = char()
                if kind == "z" && count == 1 { pos += 1; stack.append(.type(try typeNode("Protocol:Swift.BinaryInteger"))); continue }
                if kind == "a" && count == 1 { pos += 1; stack.append(.type(try typeNode("Swift.Array", nominalKind: "struct"))); continue }
                guard let name = builtins[kind] else { try decline("unknown_substitution", "unknown standard type substitution") }
                pos += 1
                for _ in 0..<count { stack.append(.type(try typeNode(name, nominalKind: "struct"))) }
            case "V", "O", "C", "P":
                if code == "P" { try decline("protocol_context", "protocol type needs separate qualification") }
                guard stack.count >= 2, case .text(let name) = stack.last! else { try decline("invalid_grammar", "nominal type lacks name/context") }
                stack.removeLast(); let ownerOperand = stack.removeLast(); let owner: String
                switch ownerOperand {
                case .type(let type):
                    guard ["struct", "enum", "class"].contains(type.nominalKind ?? ""), type.arguments.isEmpty, !type.inout else { try decline("invalid_grammar", "unsupported non-nominal or bound nominal context") }
                    owner = type.name
                case .text(let value): owner = value
                default: try decline("invalid_grammar", "invalid nominal context")
                }
                let node = try typeNode(owner + "." + name, nominalKind: nominal[code])
                try addSubstitution(.type(node)); stack.append(.type(node))
            case "s":
                let name = try identifier()
                if char() == "R" { try decline("generic_requirements", "generic protocol requirement needs separate qualification") }
                guard char() == "V", integerNames.contains(name) else { try decline("unsupported_production", "unsupported Swift nominal type") }
                pos += 1; let node = try typeNode("Swift." + name, nominalKind: "struct")
                try addSubstitution(.type(node)); stack.append(.type(node))
            case "A":
                guard let encoding = match("([1-9][0-9]{0,5})?([A-Z])"), let last = encoding.utf8.last else { try decline("unknown_substitution", "unsupported substitution encoding") }
                pos += encoding.count; let count = Int(encoding.dropLast()) ?? 1, index = Int(last) - 65
                try limit(count > limits.maxNodes, "repeat substitution limit")
                guard index < substitutions.count else { try decline("unknown_substitution", "substitution index is absent") }
                stack.append(contentsOf: Array(repeating: substitutions[index], count: count))
            case "G":
                var arguments: [SwiftBroadType] = []
                while let last = stack.last, !last.isEmpty { arguments.append(try popType(&stack)) }
                guard !stack.isEmpty else { try decline("invalid_grammar", "generic arguments lack start marker") }
                stack.removeLast(); let nominalType = try popType(&stack)
                guard nominalType.name == "Swift.Array", arguments.count == 1 else { try decline("unsupported_production", "unsupported bound generic shape") }
                let node = try typeNode(nominalType.name, Array(arguments.reversed())); try addSubstitution(.type(node)); stack.append(.type(node))
            case "x", "q":
                var depth = 0, parameterIndex = 0
                if code == "q" {
                    if char() == "d" { pos += 1; depth = try index() + 1; parameterIndex = try index() }
                    else if char() == "z" { pos += 1 }
                    else { parameterIndex = try index() + 1 }
                }
                try limit(depth > limits.maxContextDepth || parameterIndex >= limits.maxGenericParameters, "generic parameter index limit")
                stack.append(.type(try typeNode("GenericParameter", genericDepth: depth, genericIndex: parameterIndex)))
            case "z":
                let original = try popType(&stack); stack.append(.type(original.annotated(isInout: true, label: original.label)))
            case "t":
                var elements: [SwiftBroadType] = []
                while let last = stack.last, !last.isFirst { elements.append(try popType(&stack)) }
                guard !stack.isEmpty else { try decline("invalid_grammar", "tuple lacks first-element separator") }
                stack.removeLast(); elements.append(try popType(&stack)); elements.reverse()
                try limit(elements.count > limits.maxParameters, "tuple element limit")
                stack.append(.type(try typeNode("Tuple", elements)))
            case "l":
                guard genericCounts.isEmpty else { try decline("invalid_grammar", "duplicate generic signature") }; genericCounts = [1]
            case "r":
                guard genericCounts.isEmpty else { try decline("invalid_grammar", "duplicate generic signature") }
                var counts: [Int] = []
                while pos < text.count && char() != "l" {
                    if char() == "z" { pos += 1; counts.append(0) } else { counts.append(try index() + 1) }
                    try limit(counts.reduce(0, +) > limits.maxGenericParameters || counts.count > limits.maxContextDepth, "generic signature limit")
                }
                guard pos < text.count else { try decline("invalid_grammar", "unterminated generic signature") }
                pos += 1; genericCounts = counts.isEmpty ? [1] : counts
            case "R":
                let proto = try popType(&stack)
                guard proto.name == "Protocol:Swift.BinaryInteger" else { try decline("generic_requirements", "unsupported generic requirement") }
                guard char() == "z" else { try decline("generic_requirements", "unsupported generic requirement parameter index") }
                pos += 1; requirements.append(SwiftBroadGenericRequirement(protocol: "Swift.BinaryInteger", parameterDepth: 0, parameterIndex: 0))
            case "F":
                let params = try popType(&stack), result = try popType(&stack)
                let parameters = params.name == "Swift.Void" ? [] : (params.name == "Tuple" ? params.arguments : [params])
                try limit(parameters.count > limits.maxParameters, "parameter count limit")
                let labels: [String?]
                if stack.count == 1 && stack[0].isEmpty { labels = Array(repeating: nil, count: parameters.count) }
                else if stack.isEmpty && parameters.isEmpty { labels = [] }
                else if stack.count == parameters.count && stack.allSatisfy({ if case .text = $0 { return true }; return $0.isFirst }) {
                    labels = stack.map { if case .text(let name) = $0 { return name }; return nil }
                } else { try decline("invalid_grammar", "parameter label/type arity mismatch") }
                if !requirements.isEmpty && genericCounts.isEmpty { try decline("generic_requirements", "requirement lacks generic signature") }
                for requirement in requirements {
                    guard requirement.parameterDepth < genericCounts.count, requirement.parameterIndex < genericCounts[requirement.parameterDepth] else { try decline("generic_requirements", "generic requirement references an unbound parameter") }
                }
                var pending = [result] + parameters, visited: Set<ObjectIdentifier> = []
                while let node = pending.popLast() {
                    guard visited.insert(ObjectIdentifier(node)).inserted else { continue }
                    if let depth = node.genericDepth {
                        guard depth < genericCounts.count, let index = node.genericIndex, index < genericCounts[depth] else { try decline("generic_requirements", "generic parameter lacks a supported binding signature (including generic parent contexts)") }
                    }
                    pending.append(contentsOf: node.arguments)
                }
                let isStatic = char() == "Z"
                if isStatic { pos += 1; if context.isEmpty { try decline("invalid_grammar", "static function lacks nominal context") } }
                let kind = isStatic ? "static_method" : (context.last.map { $0.kind + "_instance_method" } ?? "free_function")
                let identity = SwiftBroadCallableIdentity(symbol: original, module: module, context: context, callableKind: kind,
                    functionName: function, parameterLabels: labels, parameterTypes: parameters, resultType: result, throwsFlag: throwing,
                    genericParameterCounts: genericCounts, genericRequirements: requirements)
                if pos == text.count { return identity }; return try specialization(identity)
            default: try decline("unsupported_production", "unsupported grammar operator: " + code)
            }
        }
        try decline("invalid_grammar", "missing function declaration operator")
    }
}

func parseBroadSwiftDeclaration(_ symbol: String, limits: SwiftBroadParseLimits = .init()) -> SwiftBroadDeclarationResult {
    guard symbol.utf8.allSatisfy({ $0 >= 32 && $0 < 128 }) else {
        return SwiftBroadDeclarationResult(nil, "invalid_input", "expected an ASCII external symbol without symbolic references")
    }
    guard [limits.maxSymbolLength, limits.maxIdentifierLength, limits.maxContextDepth, limits.maxNodes,
           limits.maxSubstitutions, limits.maxParameters, limits.maxTypeDepth, limits.maxGenericParameters].allSatisfy({ $0 >= 1 }) else {
        return SwiftBroadDeclarationResult(nil, "invalid_input", "limits must be positive integers")
    }
    guard symbol.count <= limits.maxSymbolLength else { return SwiftBroadDeclarationResult(nil, "resource_limit", "symbol length limit") }
    guard symbol.hasPrefix("$s") || symbol.hasPrefix("_$s") else { return SwiftBroadDeclarationResult(nil, "invalid_input", "expected stable Swift external symbol prefix") }
    let parser = SwiftBroadParser(symbol, limits)
    do { return SwiftBroadDeclarationResult(try parser.parse()) }
    catch let error as SwiftBroadDecline { return SwiftBroadDeclarationResult(nil, error.reason, error.detail, parser.pos) }
    catch { return SwiftBroadDeclarationResult(nil, "invalid_grammar", "invalid declaration", parser.pos) }
}
