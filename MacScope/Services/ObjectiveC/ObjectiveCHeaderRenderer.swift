import Foundation

/// Emits a deterministic Objective-C header (`@interface … @end`) from recovered `ObjCClass`
/// models — a standard class-dump artifact. Pure and order-stable;
/// member types come from `ObjCTypeEncoding` (which falls back to `id` rather than guess).
enum ObjectiveCHeaderRenderer {

    static func render(classes: [ObjCClass], categories: [ObjCCategory] = []) -> String {
        (classes.map(renderInterface) + categories.map(renderCategory)).joined(separator: "\n\n")
    }

    /// Renders a category as `@interface Class (Name) … @end`. Categories carry no ivars (they can't
    /// add storage); protocols the category adopts go in the `<…>` clause.
    private static func renderCategory(_ category: ObjCCategory) -> String {
        var lines: [String] = []
        var declaration = "@interface \(category.className) (\(category.name))"
        if !category.adoptedProtocols.isEmpty {
            declaration += " <\(category.adoptedProtocols.joined(separator: ", "))>"
        }
        lines.append(declaration)
        for property in category.properties { lines.append(renderProperty(property)) }
        for method in category.classMethods { lines.append(ObjCTypeEncoding.methodSignature(method)) }
        for method in category.instanceMethods { lines.append(ObjCTypeEncoding.methodSignature(method)) }
        lines.append("@end")
        return lines.joined(separator: "\n")
    }

    private static func renderInterface(_ cls: ObjCClass) -> String {
        var lines: [String] = []

        var declaration = "@interface \(cls.name)"
        if let superclass = cls.superclassName, !superclass.isEmpty {
            declaration += " : \(superclass)"
        }
        if !cls.adoptedProtocols.isEmpty {
            declaration += " <\(cls.adoptedProtocols.joined(separator: ", "))>"
        }
        lines.append(declaration)

        if !cls.ivars.isEmpty {
            lines.append("{")
            for ivar in cls.ivars {
                let type = ivar.typeEncoding.map(ObjCTypeEncoding.decode) ?? "id"
                lines.append("    \(ObjCTypeEncoding.declaration(type: type, name: ivar.name));")
            }
            lines.append("}")
        }

        for property in cls.properties {
            lines.append(renderProperty(property))
        }
        for method in cls.classMethods {
            lines.append(ObjCTypeEncoding.methodSignature(method))
        }
        for method in cls.instanceMethods {
            lines.append(ObjCTypeEncoding.methodSignature(method))
        }

        lines.append("@end")
        return lines.joined(separator: "\n")
    }

    /// Retains validated custom accessor spelling, without claiming an implementation or ABI.
    /// Invalid accessor facts must not become a declaration with invented default accessors.
    private static func renderProperty(_ property: ObjCProperty) -> String {
        let components = property.attributes.components(separatedBy: ",")
        var getter: String?
        var setter: String?
        var isReadonly = false
        for component in components {
            guard let marker = component.unicodeScalars.first else { continue }
            if marker == "R" { isReadonly = true }
            guard marker == "G" || marker == "S" else { continue }
            let selector = String(component.unicodeScalars.dropFirst())
            guard validPropertyAccessor(selector, isSetter: marker == "S") else {
                return refusedProperty(property, reason: "unsupported accessor spelling or arity")
            }
            let previous = marker == "G" ? getter : setter
            // Byte identity, not Unicode canonical equivalence: never choose another spelling.
            if let previous, !previous.utf8.elementsEqual(selector.utf8) {
                return refusedProperty(property, reason: "conflicting accessor attributes")
            }
            if marker == "G" { getter = selector } else { setter = selector }
        }
        if isReadonly && setter != nil {
            return refusedProperty(property, reason: "readonly property has a custom setter")
        }

        var type = "id"
        var attributes: [String] = []
        for component in components {
            guard let marker = component.first else { continue }
            switch marker {
            case "T": type = ObjCTypeEncoding.decode(String(component.dropFirst()))
            case "R": attributes.append("readonly")
            case "C": attributes.append("copy")
            case "&": attributes.append("strong")
            case "W": attributes.append("weak")
            case "N": attributes.append("nonatomic")
            default: break // V (backing ivar), D (dynamic), etc. retain their prior treatment.
            }
        }
        // Fixed ordering and one occurrence for byte-identical repeated accessor attributes.
        if let getter { attributes.append("getter=\(getter)") }
        if let setter { attributes.append("setter=\(setter)") }
        let attributeText = attributes.isEmpty ? "" : "(\(attributes.joined(separator: ", "))) "
        return "@property \(attributeText)\(ObjCTypeEncoding.declaration(type: type, name: property.name));"
    }

    /// Same conservative letter/underscore then letter/number/underscore subset as the
    /// private candidate identifier check, without its optional whitespace normalization.
    /// The existing candidate selector ceiling is 512 UTF-8 bytes, including setter colon.
    private static func validPropertyAccessor(_ selector: String, isSetter: Bool) -> Bool {
        guard !selector.isEmpty, selector.utf8.prefix(513).count <= 512,
              !selector.unicodeScalars.contains(where: {
                  CharacterSet.whitespacesAndNewlines.contains($0)
                      || CharacterSet.controlCharacters.contains($0)
              }) else { return false }
        let identifier: Substring
        if isSetter {
            guard selector.last == ":" else { return false }
            identifier = selector.dropLast()
        } else {
            identifier = selector[...]
        }
        guard let first = identifier.first, first == "_" || first.isLetter else { return false }
        return identifier.dropFirst().allSatisfy { $0 == "_" || $0.isLetter || $0.isNumber }
    }

    private static func refusedProperty(_ property: ObjCProperty, reason: String) -> String {
        "/* Property accessor metadata refused (\(reason)); name=\"\(propertyDiagnosticText(property.name))\"; attributes=\"\(propertyDiagnosticText(property.attributes))\" */"
    }

    /// ASCII-only bounded context. No raw slash, star, backslash, quote, line separator or
    /// control can escape the block comment. Escapes are diagnostic notation, not repaired data.
    private static func propertyDiagnosticText(_ text: String) -> String {
        var result = ""
        var byteCount = 0
        for scalar in text.unicodeScalars {
            let value = scalar.value
            let piece: String
            if (0x20...0x7E).contains(value), ![0x22, 0x2A, 0x2F, 0x5C].contains(value) {
                piece = String(scalar)
            } else {
                piece = "\\u{\(String(value, radix: 16))}"
            }
            guard byteCount + piece.utf8.count <= 253 else {
                result += "..."
                break
            }
            result += piece
            byteCount += piece.utf8.count
        }
        return result
    }
}
