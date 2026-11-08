import Foundation

/// Buildable editing scaffolds are deliberately renamed. Reference files preserve the recovered
/// interface; placeholder classes/fields do not assert original storage or protocol conformance.
enum RegenerationNominalRenderer {
    static func render(_ types: [RegenerationNominalTypeInput]) throws -> [String: Data] {
        guard types.count <= 10_000, types.allSatisfy({ $0.fields.count <= 1_000 && $0.name.utf8.count <= 4_096 }) else {
            throw RegenerationError.invalidInput("nominal type inventory exceeds export limits")
        }
        var result: [String: Data] = [:]
        for (index, type) in types.sorted(by: { a, b in
            if a.language.rawValue != b.language.rawValue { return a.language.rawValue < b.language.rawValue }
            if a.name != b.name { return a.name < b.name }
            if a.module != b.module { return (a.module ?? "") < (b.module ?? "") }
            if a.kind.rawValue != b.kind.rawValue { return a.kind.rawValue < b.kind.rawValue }
            let fieldsA = a.fields.map { [$0.name, $0.recoveredType ?? "", String($0.mutable)] }
            let fieldsB = b.fields.map { [$0.name, $0.recoveredType ?? "", String($0.mutable)] }
            return fieldsA.lexicographicallyPrecedes(fieldsB) { $0.lexicographicallyPrecedes($1) }
        }).enumerated() {
            let key = String(format: "%05d", index) + "_" + RegenerationEncoding.identifier(type.name)
            let name = "MSRG_Recovered_" + key
            let banner = "// Recovered type: " + RegenerationEncoding.annotation(type.name)
                + "\n// Editing scaffold only; no recovered storage layout or ABI compatibility is asserted.\n"
            if type.language == .swift {
                let kind = type.kind == .class ? "class" : type.kind == .enum ? "enum" : "struct"
                var lines = [banner + "import Foundation\n\(kind) \(name) {"]
                for (fieldIndex, field) in type.fields.enumerated() {
                    let fieldName = "recovered_\(fieldIndex)_" + RegenerationEncoding.identifier(field.name)
                    let fieldType = swiftType(field.recoveredType)
                    lines.append("    // Original field: " + RegenerationEncoding.annotation(field.name)
                        + "; recovered type: " + RegenerationEncoding.annotation(field.recoveredType ?? "unresolved"))
                    if type.kind == .enum {
                        lines.append("    case \(fieldName)(\(fieldType))")
                    } else {
                        lines.append("    var \(fieldName): \(fieldType) {")
                        lines.append("        get { fatalError(\"Recovered field is unimplemented\") }")
                        if field.mutable { lines.append("        set { fatalError(\"Recovered field is unimplemented\") }") }
                        lines.append("    }")
                    }
                }
                lines.append("}")
                let module = RegenerationEncoding.identifier(type.module ?? "Recovered")
                result["Sources/Swift/\(module)/type_\(key).swift"] = Data((lines.joined(separator: "\n") + "\n").utf8)
            } else if type.language == .objc {
                let basename = "type_\(key)"
                var header = [banner + "#pragma once\n#import <Foundation/Foundation.h>\n#import \"../Support/MacScopeUnresolved.h\"\n@interface \(name) : NSObject"]
                var implementation = ["#import \"\(basename).h\"", "@implementation \(name)"]
                for (fieldIndex, field) in type.fields.enumerated() {
                    let fieldName = "recovered_\(fieldIndex)_" + RegenerationEncoding.identifier(field.name)
                    let fieldType = objcType(field.recoveredType)
                    header.append("// Original field: " + RegenerationEncoding.annotation(field.name)
                        + "; encoding: " + RegenerationEncoding.annotation(field.recoveredType ?? "unresolved"))
                    header.append("@property (nonatomic, readonly) \(fieldType) \(fieldName);")
                    implementation.append("- (\(fieldType))\(fieldName) { __builtin_trap(); }")
                }
                header.append("@end"); implementation.append("@end")
                result["Sources/ObjC/\(basename).h"] = Data((header.joined(separator: "\n") + "\n").utf8)
                result["Sources/ObjC/\(basename).m"] = Data((implementation.joined(separator: "\n") + "\n").utf8)
            } else {
                throw RegenerationError.invalidInput("unsupported nominal type language")
            }
        }
        return result
    }

    private static func swiftType(_ value: String?) -> String {
        let supported: Set<String> = ["Int", "Int8", "Int16", "Int32", "Int64", "UInt", "UInt8", "UInt16", "UInt32", "UInt64",
            "Float", "Double", "Bool", "String", "Character", "Data", "Date", "UUID"]
        return value.flatMap { supported.contains($0) ? $0 : nil } ?? "MacScopeUnresolved"
    }

    private static func objcType(_ encoding: String?) -> String {
        let supported = ["c": "char", "i": "int", "s": "short", "l": "long", "q": "long long",
                         "C": "unsigned char", "I": "unsigned int", "S": "unsigned short", "L": "unsigned long", "Q": "unsigned long long",
                         "f": "float", "d": "double", "B": "BOOL", "@": "id"]
        return encoding.flatMap { supported[$0] } ?? "MacScopeUnresolved *"
    }
}
