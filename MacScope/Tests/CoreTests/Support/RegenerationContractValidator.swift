import Foundation

/// Minimal JSON Schema validator for exactly the keywords the frozen regeneration contracts use:
/// type (including type arrays and null), enum, const, required, properties, items, pattern,
/// minItems, maxItems, local `$ref`/`$defs`, `allOf` with `if`/`then`/`else`, and `not`.
/// `format` and the descriptive keywords are annotations. A keyword outside that set is refused
/// rather than ignored, so a schema amendment cannot silently weaken a check.
enum RegenerationContractValidator {
    struct Failure: Error, CustomStringConvertible {
        let path: String
        let message: String
        var description: String { "\(path): \(message)" }
    }

    private indirect enum JSON: Equatable {
        case null
        case bool(Bool)
        case number(Double)
        case string(String)
        case array([JSON])
        case object([String: JSON])

        init(_ value: Any) throws {
            switch value {
            case is NSNull: self = .null
            case let number as NSNumber:
                self = CFGetTypeID(number) == CFBooleanGetTypeID() ? .bool(number.boolValue) : .number(number.doubleValue)
            case let text as String: self = .string(text)
            case let items as [Any]: self = .array(try items.map(JSON.init))
            case let fields as [String: Any]: self = .object(try fields.mapValues(JSON.init))
            default: throw Failure(path: "$", message: "unsupported JSON value")
            }
        }
    }

    private static let annotations: Set<String> = ["$schema", "$id", "$defs", "title", "description", "format"]
    private static let keywords: Set<String> = [
        "type", "enum", "const", "required", "properties", "items", "pattern", "minItems", "maxItems",
        "$ref", "allOf", "if", "then", "else", "not",
    ]

    static func validate(_ instance: Data, schema: Data) throws {
        let root = try decode(schema, what: "schema")
        try check(try decode(instance, what: "instance"), root, root: root, path: "$")
    }

    private static func decode(_ data: Data, what: String) throws -> JSON {
        do {
            return try JSON(try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]))
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure(path: "$", message: "\(what) is not valid JSON")
        }
    }

    private static func check(_ value: JSON, _ schema: JSON, root: JSON, path: String) throws {
        guard case let .object(rules) = schema else { throw Failure(path: path, message: "schema must be an object") }
        for key in rules.keys.sorted() where !annotations.contains(key) && !keywords.contains(key) {
            throw Failure(path: path, message: "unsupported schema keyword \(key)")
        }
        if case let .string(reference)? = rules["$ref"] {
            try check(value, try resolve(reference, root: root, path: path), root: root, path: path)
        }
        if let type = rules["type"] {
            let names: [JSON]
            if case let .array(list) = type { names = list } else { names = [type] }
            guard names.contains(where: { matches(value, typeName: $0) }) else {
                throw Failure(path: path, message: "type mismatch")
            }
        }
        if case let .array(options)? = rules["enum"], !options.contains(value) {
            throw Failure(path: path, message: "not an allowed enum value")
        }
        if let constant = rules["const"], constant != value {
            throw Failure(path: path, message: "does not equal const")
        }
        if case let .string(pattern)? = rules["pattern"], case let .string(text) = value {
            guard let expression = try? NSRegularExpression(pattern: pattern),
                  expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil else {
                throw Failure(path: path, message: "does not match pattern")
            }
        }
        if case let .object(fields) = value {
            if case let .array(names)? = rules["required"] {
                for case let .string(name) in names where fields[name] == nil {
                    throw Failure(path: path + "." + name, message: "missing required property")
                }
            }
            if case let .object(properties)? = rules["properties"] {
                for name in properties.keys.sorted() {
                    if let child = fields[name], let childSchema = properties[name] {
                        try check(child, childSchema, root: root, path: path + "." + name)
                    }
                }
            }
        }
        if case let .array(items) = value {
            if case let .number(minimum)? = rules["minItems"], Double(items.count) < minimum {
                throw Failure(path: path, message: "fewer items than minItems")
            }
            if case let .number(maximum)? = rules["maxItems"], Double(items.count) > maximum {
                throw Failure(path: path, message: "more items than maxItems")
            }
            if let itemSchema = rules["items"] {
                for (index, item) in items.enumerated() {
                    try check(item, itemSchema, root: root, path: path + "[\(index)]")
                }
            }
        }
        if case let .array(branches)? = rules["allOf"] {
            for branch in branches { try check(value, branch, root: root, path: path) }
        }
        if let condition = rules["if"] {
            if (try? check(value, condition, root: root, path: path)) != nil {
                if let then = rules["then"] { try check(value, then, root: root, path: path) }
            } else if let otherwise = rules["else"] {
                try check(value, otherwise, root: root, path: path)
            }
        }
        if let negated = rules["not"], (try? check(value, negated, root: root, path: path)) != nil {
            throw Failure(path: path, message: "matches a schema it must not match")
        }
    }

    private static func resolve(_ reference: String, root: JSON, path: String) throws -> JSON {
        guard reference.hasPrefix("#/") else { throw Failure(path: path, message: "only local $ref is supported") }
        var node = root
        for part in reference.dropFirst(2).split(separator: "/") {
            guard case let .object(fields) = node, let next = fields[String(part)] else {
                throw Failure(path: path, message: "unresolved $ref \(reference)")
            }
            node = next
        }
        return node
    }

    private static func matches(_ value: JSON, typeName: JSON) -> Bool {
        guard case let .string(name) = typeName else { return false }
        switch (name, value) {
        case ("null", .null), ("boolean", .bool), ("string", .string), ("array", .array), ("object", .object), ("number", .number):
            return true
        case let ("integer", .number(number)):
            return number == number.rounded() && number.isFinite
        default:
            return false
        }
    }
}
