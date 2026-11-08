import Foundation

indirect enum SwiftOutcomeJSON: Equatable, Sendable {
    case null, bool(Bool), integer(Int128), string(String)
    case array([SwiftOutcomeJSON]), object([String: SwiftOutcomeJSON])

    var object: [String: SwiftOutcomeJSON]? { if case .object(let v) = self { return v }; return nil }
    var array: [SwiftOutcomeJSON]? { if case .array(let v) = self { return v }; return nil }
    var string: String? { if case .string(let v) = self { return v }; return nil }
    var integer: Int128? { if case .integer(let v) = self { return v }; return nil }
    subscript(_ key: String) -> SwiftOutcomeJSON {
        get { object?[key] ?? .null }
        set { var values = object ?? [:]; values[key] = newValue; self = .object(values) }
    }
    var isTruthy: Bool {
        switch self {
        case .null: return false
        case .bool(let v): return v
        case .integer(let v): return v != 0
        case .string(let v): return !v.isEmpty
        case .array(let v): return !v.isEmpty
        case .object(let v): return !v.isEmpty
        }
    }
}

struct SwiftOutcomeError: Error, Equatable, Sendable { let code: String }
let witnessModel = "swift-outcome-witness-v2"
let validationModel = "swift-outcome-validation-v2"

struct BroadWitnessLimits: Equatable, Sendable {
    let maxInstructions: Int, maxBlocks: Int, maxEdges: Int, maxWork: Int
    let maxDepth: Int, maxStateEntries: Int, maxProvenanceNodes: Int, maxContainerItems: Int
    let maxString: Int, maxBytes: Int, maxAggregateBytes: Int, postCallWindow: Int

    // The exact no-argument overload is nonthrowing; all defaults satisfy the caps.
    init() {
        maxInstructions = 512; maxBlocks = 512; maxEdges = 2048; maxWork = 65536
        maxDepth = 32; maxStateEntries = 64; maxProvenanceNodes = 512; maxContainerItems = 16384
        maxString = 2048; maxBytes = 262144; maxAggregateBytes = 16777216; postCallWindow = 16
    }
    init(maxInstructions: Int = 512, maxBlocks: Int = 512, maxEdges: Int = 2048,
         maxWork: Int = 65536, maxDepth: Int = 32, maxStateEntries: Int = 64,
         maxProvenanceNodes: Int = 512, maxContainerItems: Int = 16384,
         maxString: Int = 2048, maxBytes: Int = 262144,
         maxAggregateBytes: Int = 16777216, postCallWindow: Int = 16) throws {
        let checks: [(String, Int, Int)] = [
            ("max_instructions", maxInstructions, 4096), ("max_blocks", maxBlocks, 4096),
            ("max_edges", maxEdges, 16384), ("max_work", maxWork, 262144),
            ("max_depth", maxDepth, 64), ("max_state_entries", maxStateEntries, 128),
            ("max_provenance_nodes", maxProvenanceNodes, 4096),
            ("max_container_items", maxContainerItems, 65536), ("max_string", maxString, 8192),
            ("max_bytes", maxBytes, 262144), ("max_aggregate_bytes", maxAggregateBytes, 16777216),
            ("post_call_window", postCallWindow, 16)]
        for (name, value, cap) in checks where value < 0 || value > cap {
            throw SwiftOutcomeError(code: "invalid_broad_witness_limit:" + name)
        }
        self.maxInstructions = maxInstructions; self.maxBlocks = maxBlocks
        self.maxEdges = maxEdges; self.maxWork = maxWork; self.maxDepth = maxDepth
        self.maxStateEntries = maxStateEntries; self.maxProvenanceNodes = maxProvenanceNodes
        self.maxContainerItems = maxContainerItems; self.maxString = maxString
        self.maxBytes = maxBytes; self.maxAggregateBytes = maxAggregateBytes
        self.postCallWindow = postCallWindow
    }
}

struct BroadWitnessIdentity: Equatable, Sendable {
    let sliceSHA256: String, containerSHA256: String, callPC: String
    let callerStartPC: String, calleeStartPC: String
}
struct BroadInstruction: Equatable, Sendable {
    let pc: String, word: String, sliceOffset: String, containerOffset: String, kind: String
}

enum SwiftOutcomeWitnessCodec {
    static func preflight(_ value: SwiftOutcomeJSON, limits: BroadWitnessLimits = BroadWitnessLimits()) throws -> Int {
        var todo: [(SwiftOutcomeJSON, Int)] = [(value, 0)]
        var items = 0, budget = 0
        while let (node, depth) = todo.popLast() {
            items += 1
            guard items <= limits.maxContainerItems, depth <= limits.maxDepth else {
                throw SwiftOutcomeError(code: "witness_structure_limit")
            }
            switch node {
            case .object(let rows):
                guard rows.count <= limits.maxContainerItems - items - todo.count else {
                    throw SwiftOutcomeError(code: "witness_structure_limit")
                }
                budget += 2 + rows.count * 2
                for key in scalarSorted(rows.keys) {
                    let count = key.unicodeScalars.count
                    guard count <= limits.maxString else { throw SwiftOutcomeError(code: "witness_key_limit") }
                    budget += 2 + count * 6
                    todo.append((rows[key]!, depth + 1))
                }
            case .array(let rows):
                guard rows.count <= limits.maxContainerItems - items - todo.count else {
                    throw SwiftOutcomeError(code: "witness_structure_limit")
                }
                budget += 2 + rows.count * 2
                todo.append(contentsOf: rows.map { ($0, depth + 1) })
            case .string(let text):
                guard text.unicodeScalars.count <= limits.maxString else {
                    throw SwiftOutcomeError(code: "witness_string_limit")
                }
                budget += 2 + text.unicodeScalars.count * 6
            case .integer(let number):
                guard number >= -(Int128(1) << 64), number < Int128(1) << 64 else {
                    throw SwiftOutcomeError(code: "witness_integer_limit")
                }
                budget += 21
            case .null, .bool: budget += 5
            }
            guard budget <= limits.maxBytes else { throw SwiftOutcomeError(code: "witness_byte_limit") }
        }
        return items
    }

    static func scalarSorted<S: Sequence>(_ keys: S) -> [String] where S.Element == String {
        keys.sorted { $0.unicodeScalars.lexicographicallyPrecedes($1.unicodeScalars) }
    }

    static func canonicalBytes(_ value: SwiftOutcomeJSON) -> Data {
        Data(render(value, spaced: false).utf8)
    }

    // v1 uses Python's default separators; v2 uses compact separators.
    static func render(_ value: SwiftOutcomeJSON, spaced: Bool) -> String {
        let separator = spaced ? ", " : ","
        switch value {
        case .null: return "null"
        case .bool(let flag): return flag ? "true" : "false"
        case .integer(let number): return String(number)
        case .string(let text): return quote(text)
        case .array(let values): return "[" + values.map { render($0, spaced: spaced) }.joined(separator: separator) + "]"
        case .object(let values):
            return "{" + scalarSorted(values.keys).map {
                quote($0) + (spaced ? ": " : ":") + render(values[$0]!, spaced: spaced)
            }.joined(separator: separator) + "}"
        }
    }

    private static func quote(_ text: String) -> String {
        var result = "\""
        func escaped(_ value: UInt32) -> String {
            let digits = String(value, radix: 16)
            return "\\u" + String(repeating: "0", count: 4 - digits.count) + digits
        }
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 0x22: result += "\\\""
            case 0x5c: result += "\\\\"
            case 8: result += "\\b"
            case 9: result += "\\t"
            case 10: result += "\\n"
            case 12: result += "\\f"
            case 13: result += "\\r"
            case 0x20...0x7e: result.unicodeScalars.append(scalar)
            case 0x10000...0x10ffff:
                let point = scalar.value - 0x10000
                result += escaped(0xd800 + (point >> 10)) + escaped(0xdc00 + (point & 0x3ff))
            default: result += escaped(scalar.value)
            }
        }
        return result + "\""
    }

    static func encode(_ value: SwiftOutcomeJSON, limits: BroadWitnessLimits = BroadWitnessLimits()) throws -> Data {
        _ = try preflight(value, limits: limits)
        guard value.object != nil, value["model_version"] == .string(witnessModel),
              value["status"] == .string("unresolved"), value["eligible"] == .bool(false) else {
            throw SwiftOutcomeError(code: "candidate_only_contract")
        }
        let bytes = canonicalBytes(value)
        guard bytes.count <= limits.maxBytes else { throw SwiftOutcomeError(code: "witness_byte_limit") }
        return bytes
    }

    static func publicRecord(_ value: SwiftOutcomeJSON, limits: BroadWitnessLimits = BroadWitnessLimits()) throws -> SwiftOutcomeJSON {
        // Explicit stack keeps the traversal bounded before any recursive encoding.
        enum Task { case visit(SwiftOutcomeJSON, Int); case list(Int); case dictionary([String]) }
        var pending: [Task] = [.visit(value, 0)]
        var output: [SwiftOutcomeJSON] = []
        var count = 0, scheduled = 1
        while let task = pending.popLast() {
            switch task {
            case .list(let size):
                let values = Array(output.suffix(size).reversed()); output.removeLast(size); output.append(.array(values))
            case .dictionary(let keys):
                let values = Array(output.suffix(keys.count)); output.removeLast(keys.count)
                output.append(.object(Dictionary(uniqueKeysWithValues: zip(keys, values))))
            case .visit(let node, let depth):
                scheduled -= 1; count += 1
                guard count <= limits.maxContainerItems, depth <= limits.maxDepth else {
                    throw SwiftOutcomeError(code: "witness_structure_limit")
                }
                switch node {
                case .object(let rows):
                    guard rows.count <= limits.maxContainerItems - count - scheduled else { throw SwiftOutcomeError(code: "witness_structure_limit") }
                    let allKeys = scalarSorted(rows.keys)
                    for key in allKeys where key.unicodeScalars.count > limits.maxString { throw SwiftOutcomeError(code: "witness_key_limit") }
                    let keys = allKeys.filter { $0 != "binding" && !$0.hasSuffix("_binding") }
                    pending.append(.dictionary(keys))
                    for key in keys.reversed() { pending.append(.visit(rows[key]!, depth + 1)) }
                    scheduled += keys.count
                case .array(let values):
                    guard values.count <= limits.maxContainerItems - count - scheduled else { throw SwiftOutcomeError(code: "witness_structure_limit") }
                    pending.append(.list(values.count))
                    for child in values { pending.append(.visit(child, depth + 1)) }
                    scheduled += values.count
                default: output.append(node)
                }
            }
        }
        let result = output[0]
        _ = try preflight(result, limits: limits)
        return result
    }

    static func parse(_ raw: Data, limits: BroadWitnessLimits = BroadWitnessLimits()) throws -> SwiftOutcomeJSON {
        guard raw.count <= limits.maxBytes else { throw SwiftOutcomeError(code: "witness_byte_limit") }
        guard let text = String(data: raw, encoding: .utf8) else { throw SwiftOutcomeError(code: "malformed_witness_json") }
        var depth = 0, tokens = 0
        var quoted = false, escape = false, atom = false
        for scalar in text.unicodeScalars {
            let char = scalar.value
            if quoted {
                if escape { escape = false }
                else if char == 92 { escape = true }
                else if char == 34 { quoted = false }
            } else if char == 34 { quoted = true; tokens += 1; atom = false }
            else if char == 91 || char == 123 {
                tokens += 1; atom = false; depth += 1
                if depth > limits.maxDepth { throw SwiftOutcomeError(code: "witness_structure_limit") }
            } else if char == 93 || char == 125 { depth -= 1; atom = false }
            else if [44, 58, 32, 9, 13, 10].contains(char) { atom = false }
            else if !atom { tokens += 1; atom = true }
            if tokens > limits.maxContainerItems { throw SwiftOutcomeError(code: "witness_structure_limit") }
        }
        var reader = Reader(input: Array(text.unicodeScalars))
        let result = try reader.value()
        reader.whitespace()
        guard reader.cursor == reader.input.count else { throw SwiftOutcomeError(code: "malformed_witness_json") }
        _ = try preflight(result, limits: limits)
        guard result.object != nil else { throw SwiftOutcomeError(code: "witness_object_required") }
        return result
    }

    private struct Reader {
        let input: [Unicode.Scalar]
        var cursor = 0
        var current: UInt32? { cursor < input.count ? input[cursor].value : nil }
        mutating func whitespace() { while let char = current, [32, 9, 13, 10].contains(char) { cursor += 1 } }
        func malformed() -> SwiftOutcomeError { SwiftOutcomeError(code: "malformed_witness_json") }
        mutating func take(_ wanted: UInt32) throws { guard current == wanted else { throw malformed() }; cursor += 1 }
        mutating func keyword(_ word: String) throws {
            for scalar in word.unicodeScalars { try take(scalar.value) }
        }
        mutating func value() throws -> SwiftOutcomeJSON {
            whitespace()
            switch current {
            case 123:
                cursor += 1; whitespace(); var pairs: [(String, SwiftOutcomeJSON)] = []
                if current == 125 { cursor += 1; return .object([:]) }
                while true {
                    let key = try string(); whitespace(); try take(58)
                    let child = try value()
                    pairs.append((key, child)); whitespace()
                    if current == 125 {
                        cursor += 1
                        var values: [String: SwiftOutcomeJSON] = [:]
                        for (name, value) in pairs {
                            // Swift String keys equate canonically equivalent scalar spellings.
                            guard values[name] == nil else { throw SwiftOutcomeError(code: "duplicate_json_key") }
                            values[name] = value
                        }
                        return .object(values)
                    }
                    try take(44); whitespace()
                }
            case 91:
                cursor += 1; whitespace(); var values: [SwiftOutcomeJSON] = []
                if current == 93 { cursor += 1; return .array(values) }
                while true {
                    values.append(try value()); whitespace()
                    if current == 93 { cursor += 1; return .array(values) }
                    try take(44)
                }
            case 34: return .string(try string())
            case 116: try keyword("true"); return .bool(true)
            case 102: try keyword("false"); return .bool(false)
            case 110: try keyword("null"); return .null
            case 78: try keyword("NaN"); throw SwiftOutcomeError(code: "non_integer_json_number")
            case 73: try keyword("Infinity"); throw SwiftOutcomeError(code: "non_integer_json_number")
            case 45, .some(48...57): return try number()
            default: throw malformed()
            }
        }
        mutating func number() throws -> SwiftOutcomeJSON {
            let start = cursor
            if current == 45 {
                cursor += 1
                if current == 73 { try keyword("Infinity"); throw SwiftOutcomeError(code: "non_integer_json_number") }
            }
            if current == 48 { cursor += 1 }
            else {
                guard let first = current, (49...57).contains(first) else { throw malformed() }
                while let digit = current, (48...57).contains(digit) { cursor += 1 }
            }
            var floating = false
            if current == 46, cursor + 1 < input.count, (48...57).contains(input[cursor + 1].value) {
                floating = true; cursor += 1
                while let digit = current, (48...57).contains(digit) { cursor += 1 }
            }
            if current == 101 || current == 69 {
                var exponent = cursor + 1
                if exponent < input.count, input[exponent].value == 43 || input[exponent].value == 45 { exponent += 1 }
                if exponent < input.count, (48...57).contains(input[exponent].value) {
                    floating = true; cursor = exponent
                    while let digit = current, (48...57).contains(digit) { cursor += 1 }
                }
            }
            if floating { throw SwiftOutcomeError(code: "non_integer_json_number") }
            let text = String(String.UnicodeScalarView(input[start..<cursor]))
            guard text.count <= 21, let number = Int128(text), number >= -(Int128(1) << 64), number < Int128(1) << 64 else {
                throw SwiftOutcomeError(code: "witness_integer_limit")
            }
            return .integer(number)
        }
        mutating func hex4() throws -> UInt32 {
            var value: UInt32 = 0
            for _ in 0..<4 {
                guard let char = current else { throw malformed() }
                let digit: UInt32
                switch char {
                case 48...57: digit = char - 48
                case 65...70: digit = char - 55
                case 97...102: digit = char - 87
                default: throw malformed()
                }
                cursor += 1; value = value * 16 + digit
            }
            return value
        }
        mutating func string() throws -> String {
            try take(34); var result = String.UnicodeScalarView()
            while let char = current {
                if char == 34 { cursor += 1; return String(result) }
                guard char >= 0x20 else { throw malformed() }
                if char != 92 { result.append(input[cursor]); cursor += 1; continue }
                cursor += 1
                guard let escaped = current else { throw malformed() }
                cursor += 1
                let scalar: UInt32
                switch escaped {
                case 34, 92, 47: scalar = escaped
                case 98: scalar = 8
                case 102: scalar = 12
                case 110: scalar = 10
                case 114: scalar = 13
                case 116: scalar = 9
                case 117:
                    let first = try hex4()
                    if (0xd800...0xdbff).contains(first) {
                        try take(92); try take(117)
                        let second = try hex4()
                        guard (0xdc00...0xdfff).contains(second) else { throw malformed() }
                        scalar = 0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                    } else {
                        guard !(0xdc00...0xdfff).contains(first) else { throw malformed() }
                        scalar = first
                    }
                default: throw malformed()
                }
                guard let value = Unicode.Scalar(scalar) else { throw malformed() }
                result.append(value)
            }
            throw malformed()
        }
    }
}

func swiftOutcomeHex<T: BinaryInteger>(_ value: T) -> String {
    value < 0 ? "-0x" + String(value.magnitude, radix: 16) : "0x" + String(value, radix: 16)
}

func swiftOutcomeWord(_ value: UInt32) -> String {
    let text = String(value, radix: 16)
    return "0x" + String(repeating: "0", count: 8 - text.count) + text
}

// Preserve the donor's caught Python container-error strings for typed JSON inputs.
func swiftOutcomePythonType(_ value: SwiftOutcomeJSON) -> String {
    switch value { case .null: return "NoneType"; case .bool: return "bool"; case .integer: return "int"; case .string: return "str"; case .array: return "list"; case .object: return "dict" }
}
func swiftOutcomeGet(_ value: SwiftOutcomeJSON, _ key: String, default fallback: SwiftOutcomeJSON = .null) throws -> SwiftOutcomeJSON {
    guard let rows = value.object else {
        throw SwiftOutcomeError(code: "'" + swiftOutcomePythonType(value) + "' object has no attribute 'get'")
    }
    return rows[key] ?? fallback
}
func swiftOutcomeItem(_ value: SwiftOutcomeJSON, _ key: String) throws -> SwiftOutcomeJSON {
    if let rows = value.object {
        guard let child = rows[key] else { throw SwiftOutcomeError(code: "'" + key + "'") }
        return child
    }
    if value.array != nil { throw SwiftOutcomeError(code: "list indices must be integers or slices, not str") }
    if value.string != nil { throw SwiftOutcomeError(code: "string indices must be integers, not 'str'") }
    throw SwiftOutcomeError(code: "'" + swiftOutcomePythonType(value) + "' object is not subscriptable")
}
func swiftOutcomeLast(_ value: SwiftOutcomeJSON) throws -> SwiftOutcomeJSON {
    switch value {
    case .array(let rows):
        guard let last = rows.last else { throw SwiftOutcomeError(code: "list index out of range") }
        return last
    case .string(let text):
        guard let last = text.unicodeScalars.last else { throw SwiftOutcomeError(code: "string index out of range") }
        return .string(String(last))
    case .object: throw SwiftOutcomeError(code: "-1")
    default: throw SwiftOutcomeError(code: "'" + swiftOutcomePythonType(value) + "' object is not subscriptable")
    }
}
