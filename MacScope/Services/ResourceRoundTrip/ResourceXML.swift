import Foundation

enum ResourceXML {
    static func escaped(_ value: String) throws -> String {
        guard value.unicodeScalars.allSatisfy({ scalar in
            let v = scalar.value
            return v == 9 || v == 10 || v == 13 || (32...0xd7ff).contains(v)
                || (0xe000...0xfffd).contains(v) || (0x10000...0x10ffff).contains(v)
        }) else { throw RegenerationError.invalidInput("resource contains text that XML 1.0 cannot represent") }
        return value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;").replacingOccurrences(of: "'", with: "&apos;")
            .replacingOccurrences(of: "\r", with: "&#13;").replacingOccurrences(of: "\n", with: "&#10;")
            .replacingOccurrences(of: "\t", with: "&#9;")
    }

    static func element(_ name: String, attributes: [String: String], children: [String] = []) throws -> String {
        let fields = try attributes.keys.sorted().map { key in "\(key)=\"\(try escaped(attributes[key] ?? ""))\"" }.joined(separator: " ")
        let opening = "<" + name + (fields.isEmpty ? "" : " " + fields)
        return children.isEmpty ? opening + "/>" : opening + ">\n" + children.joined(separator: "\n") + "\n</" + name + ">"
    }
}
