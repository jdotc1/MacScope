import Foundation
import ExternalMCP
import NetworkEvidenceCore

/// A deliberately closed, bounded JSON Schema subset for vendor input contracts.
/// Unsupported assertions (including regex and references) fail closed. The adapter never
/// treats successful JSON decoding as evidence that tool arguments match an advertised schema.
enum ProxymanSchemaValidator {
    private static let annotations: Set<String> = [
        "$schema", "$id", "title", "description", "default", "examples", "deprecated", "readOnly", "writeOnly"
    ]
    private static let assertions: Set<String> = [
        "type", "properties", "required", "additionalProperties", "items", "enum", "const",
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minItems", "maxItems",
        "minLength", "maxLength", "minProperties", "maxProperties", "uniqueItems", "anyOf", "oneOf", "allOf", "not", "format"
    ]
    private static let types: Set<String> = ["object", "array", "string", "integer", "number", "boolean", "null"]

    static func validate(_ arguments: MCPJSONValue, against schema: MCPJSONValue, tool: String) throws {
        do {
            var budget = 512
            try verify(schema, depth: 0, budget: &budget)
            var valueBudget = 4096
            try boundValue(arguments, depth: 0, budget: &valueBudget)
            try match(arguments, schema: schema, depth: 0)
        } catch {
            throw ProxymanAdapterError.schemaIncompatible(tool)
        }
    }

    static func supports(_ arguments: MCPJSONValue, schema: MCPJSONValue) -> Bool {
        (try? validate(arguments, against: schema, tool: "schema")) != nil
    }

    private enum Invalid: Error { case schema, value }
    private static func require(_ value: Bool) throws { if !value { throw Invalid.schema } }

    private static func verify(_ schema: MCPJSONValue, depth: Int, budget: inout Int) throws {
        budget -= 1
        try require(depth <= 16 && budget >= 0)
        if case .bool = schema { return }
        guard case .object(let object) = schema else { throw Invalid.schema }
        try require(object.count <= 64 && Set(object.keys).isSubset(of: annotations.union(assertions)))
        if let type = object["type"] {
            let names: [String]
            if let one = type.pString { names = [one] }
            else if let array = type.pArray, array.count <= 7, array.allSatisfy({ $0.pString != nil }) { names = array.compactMap(\.pString) }
            else { throw Invalid.schema }
            try require(!names.isEmpty && Set(names).count == names.count && Set(names).isSubset(of: types))
        }
        if let properties = object["properties"] {
            guard let properties = properties.pObject else { throw Invalid.schema }
            try require(properties.count <= 64 && properties.keys.allSatisfy { $0.utf8.count <= 128 })
            for value in properties.values { try verify(value, depth: depth + 1, budget: &budget) }
        }
        if let required = object["required"] {
            guard let values = required.pArray, values.count <= 64, values.allSatisfy({ $0.pString != nil }) else { throw Invalid.schema }
            try require(Set(values).count == values.count)
        }
        for key in ["additionalProperties", "items", "not"] {
            if let value = object[key] { try verify(value, depth: depth + 1, budget: &budget) }
        }
        for key in ["anyOf", "oneOf", "allOf"] {
            if let value = object[key] {
                guard let array = value.pArray, (1...8).contains(array.count) else { throw Invalid.schema }
                for child in array { try verify(child, depth: depth + 1, budget: &budget) }
            }
        }
        if let values = object["enum"] {
            guard let array = values.pArray, (1...64).contains(array.count) else { throw Invalid.schema }
            for value in array { var remaining = 128; try boundValue(value, depth: 0, budget: &remaining) }
        }
        if let value = object["const"] { var remaining = 128; try boundValue(value, depth: 0, budget: &remaining) }
        for key in ["minItems", "maxItems", "minLength", "maxLength", "minProperties", "maxProperties"] {
            if let value = object[key] { try require(value.pInt.map { (0...1_000_000).contains($0) } == true) }
        }
        for key in ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] {
            if let value = object[key] { try require(value.pNumber != nil) }
        }
        if let value = object["uniqueItems"] { try require(value.pBool != nil) }
        if let value = object["format"] {
            try require(value.pString.map { ["uri", "uri-reference", "uuid", "date-time", "hostname"].contains($0) } == true)
        }
    }

    static func boundValue(_ value: MCPJSONValue, depth: Int = 0, budget: inout Int) throws {
        budget -= 1
        guard depth <= 20, budget >= 0 else { throw Invalid.value }
        switch value {
        case .null, .bool, .int: break
        case .double(let value): guard value.isFinite else { throw Invalid.value }
        case .string(let value): guard value.utf8.count <= 524_288 else { throw Invalid.value }
        case .array(let values):
            guard values.count <= 1024 else { throw Invalid.value }
            for value in values { try boundValue(value, depth: depth + 1, budget: &budget) }
        case .object(let values):
            guard values.count <= 1024, values.keys.allSatisfy({ $0.utf8.count <= 4096 }) else { throw Invalid.value }
            for value in values.values { try boundValue(value, depth: depth + 1, budget: &budget) }
        case .data: throw Invalid.value
        }
    }

    private static func match(_ value: MCPJSONValue, schema: MCPJSONValue, depth: Int) throws {
        guard depth <= 16 else { throw Invalid.value }
        if case .bool(let allowed) = schema { if !allowed { throw Invalid.value }; return }
        guard let s = schema.pObject else { throw Invalid.schema }
        if let values = s["enum"]?.pArray, !values.contains(value) { throw Invalid.value }
        if let constant = s["const"], constant != value { throw Invalid.value }
        if let type = s["type"] {
            let names = type.pString.map { [$0] } ?? type.pArray?.compactMap(\.pString) ?? []
            guard names.contains(where: { isType(value, $0) }) else { throw Invalid.value }
        }
        for child in s["allOf"]?.pArray ?? [] { try match(value, schema: child, depth: depth + 1) }
        if let alternatives = s["anyOf"]?.pArray,
           !alternatives.contains(where: { (try? match(value, schema: $0, depth: depth + 1)) != nil }) { throw Invalid.value }
        if let alternatives = s["oneOf"]?.pArray,
           alternatives.filter({ (try? match(value, schema: $0, depth: depth + 1)) != nil }).count != 1 { throw Invalid.value }
        if let forbidden = s["not"], (try? match(value, schema: forbidden, depth: depth + 1)) != nil { throw Invalid.value }
        switch value {
        case .object(let object):
            try count(object.count, minimum: s["minProperties"], maximum: s["maxProperties"])
            for name in s["required"]?.pArray?.compactMap(\.pString) ?? [] {
                guard object[name] != nil else { throw Invalid.value }
            }
            let properties = s["properties"]?.pObject ?? [:]
            for (key, child) in object {
                if let constraint = properties[key] { try match(child, schema: constraint, depth: depth + 1) }
                else if let constraint = s["additionalProperties"] { try match(child, schema: constraint, depth: depth + 1) }
            }
        case .array(let array):
            try count(array.count, minimum: s["minItems"], maximum: s["maxItems"])
            if s["uniqueItems"]?.pBool == true, Set(array).count != array.count { throw Invalid.value }
            if let item = s["items"] { for child in array { try match(child, schema: item, depth: depth + 1) } }
        case .string(let string):
            try count(string.unicodeScalars.count, minimum: s["minLength"], maximum: s["maxLength"])
            if let format = s["format"]?.pString { try checkFormat(string, format: format) }
        case .int, .double:
            guard let number = value.pNumber else { throw Invalid.value }
            if let minimum = s["minimum"]?.pNumber, number < minimum { throw Invalid.value }
            if let maximum = s["maximum"]?.pNumber, number > maximum { throw Invalid.value }
            if let minimum = s["exclusiveMinimum"]?.pNumber, number <= minimum { throw Invalid.value }
            if let maximum = s["exclusiveMaximum"]?.pNumber, number >= maximum { throw Invalid.value }
        case .bool, .null: break
        case .data: throw Invalid.value
        }
    }

    private static func count(_ count: Int, minimum: MCPJSONValue?, maximum: MCPJSONValue?) throws {
        if let minimum = minimum?.pInt, count < minimum { throw Invalid.value }
        if let maximum = maximum?.pInt, count > maximum { throw Invalid.value }
    }

    private static func isType(_ value: MCPJSONValue, _ type: String) -> Bool {
        switch (type, value) {
        case ("null", .null), ("boolean", .bool), ("string", .string), ("array", .array), ("object", .object),
             ("number", .int), ("number", .double), ("integer", .int): true
        case ("integer", .double(let number)): number.isFinite && number.rounded() == number
        default: false
        }
    }

    private static func checkFormat(_ string: String, format: String) throws {
        let valid: Bool
        switch format {
        case "uuid": valid = UUID(uuidString: string) != nil
        case "hostname": valid = ProxymanMinimizer.canonicalHost(string) != nil
        case "date-time":
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            valid = formatter.date(from: string) != nil || ISO8601DateFormatter().date(from: string) != nil
        case "uri": valid = URLComponents(string: string)?.scheme != nil && !string.contains(where: \.isWhitespace)
        case "uri-reference": valid = URLComponents(string: string) != nil && !string.contains(where: \.isWhitespace)
        default: valid = false
        }
        if !valid { throw Invalid.value }
    }
}
