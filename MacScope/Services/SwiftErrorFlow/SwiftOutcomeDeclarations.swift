import Foundation

struct SwiftThrowingDeclaration: Equatable, Sendable {
    let symbol: String
    let module: String
    let callableKind: String
    let typeName: String?
    let functionName: String
    let parameterTypes: [String]
    let resultType: String
    let errorRegister = "x21"
    let convention = "swift_sync_untyped_throws"
    let evidenceSource = "exact_external_symbol_grammar"

    func record() -> SwiftOutcomeJSON {
        var row: [String: SwiftOutcomeJSON] = [
            "module": .string(module), "name": .string(functionName),
            "parameters": .array(parameterTypes.map(SwiftOutcomeJSON.string)),
            "result": .string(resultType), "convention": .string(convention),
            "error_register": .string(errorRegister), "source": .string(evidenceSource)]
        if callableKind == "struct_instance_method" {
            row["callable_kind"] = .string(callableKind)
            row["type_name"] = typeName.map(SwiftOutcomeJSON.string) ?? .null
            row["declaration_model_version"] = .string("swift-throwing-declarations-v1")
        }
        return .object(row)
    }
}

func parseThrowingDeclaration(_ symbol: String, allowMethods: Bool = false) -> SwiftThrowingDeclaration? {
    let name = symbol.hasPrefix("_$s") ? String(symbol.dropFirst()) : symbol
    guard name.hasPrefix("$s"), name.unicodeScalars.count <= 512 else { return nil }
    let chars = Array(name.unicodeScalars)
    var cursor = 2
    func isHead(_ scalar: Unicode.Scalar) -> Bool {
        (65...90).contains(scalar.value) || (97...122).contains(scalar.value) || scalar.value == 95
    }
    func identifier() -> String? {
        guard cursor < chars.count, (49...57).contains(chars[cursor].value) else { return nil }
        var size = 0, digits = 0
        while cursor < chars.count, digits < 3, (48...57).contains(chars[cursor].value) {
            size = size * 10 + Int(chars[cursor].value - 48); cursor += 1; digits += 1
        }
        guard size <= 128, size <= chars.count - cursor else { return nil }
        let value = chars[cursor..<(cursor + size)]; cursor += size
        guard let first = value.first, isHead(first), value.allSatisfy({ isHead($0) || (48...57).contains($0.value) }) else { return nil }
        return String(String.UnicodeScalarView(value))
    }
    guard let module = identifier(), let second = identifier() else { return nil }
    var kind = "free_function", owner: String?, function = second
    if cursor < chars.count, chars[cursor].value == 86 {
        guard allowMethods else { return nil }
        cursor += 1
        guard let method = identifier() else { return nil }
        function = method; owner = second; kind = "struct_instance_method"
    }
    let suffix = String(String.UnicodeScalarView(chars[cursor...]))
    let parameters: [String], result: String
    switch suffix {
    case "yS2iKF": parameters = ["Swift.Int"]; result = "Swift.Int"
    case "yySiKF": parameters = ["Swift.Int"]; result = "Swift.Void"
    case "SiyKF": parameters = []; result = "Swift.Int"
    case "yyKF": guard owner == nil else { return nil }; parameters = []; result = "Swift.Void"
    default: return nil
    }
    return SwiftThrowingDeclaration(symbol: symbol, module: module, callableKind: kind,
        typeName: owner, functionName: function, parameterTypes: parameters, resultType: result)
}
