import Foundation

/// Source-like recovered declarations only; neither completeness nor executable/ABI evidence.
/// This independent opt-in surface does not alter class/category header rendering.
enum ObjectiveCProtocolRenderer {
    private static let maximumRecords = 1_024
    private static let maximumMembers = 4_096
    private static let maximumInputBytes = 1_048_576
    private static let maximumOutputBytes = 2_097_152

    static func render(protocols: [ObjCProtocol]) -> String {
        let heading = "// Recovered Objective-C protocol declarations; completeness unknown.\n"
        guard admitted(protocols) else {
            return heading + "// Protocol rendering unavailable: captured input exceeds bounded limits.\n"
        }
        guard !protocols.isEmpty else {
            return heading + "// No protocol declarations were recovered; absence is not completeness.\n"
        }
        // Compare exact retained records, including method arrays and property facts. No winner
        // is selected for either conflicting descriptor contents or duplicate names.
        var firstByAddress: [UInt64: RecordIdentity] = [:]
        var conflictingAddresses = Set<UInt64>()
        var addressByName: [[UInt8]: UInt64] = [:]
        var conflictingNames = Set<[UInt8]>()
        for record in protocols {
            let identity = RecordIdentity(record)
            let name = Array(record.name.utf8)
            if let first = firstByAddress[record.address] {
                if first != identity { conflictingAddresses.insert(record.address) }
            } else { firstByAddress[record.address] = identity }
            if let address = addressByName[name], address != record.address {
                conflictingNames.insert(name)
            } else { addressByName[name] = record.address }
        }
        var seen = Set<RecordIdentity>()
        var output = heading
        var outputBytes = heading.utf8.count
        for record in protocols where seen.insert(RecordIdentity(record)).inserted {
            let address = "0x" + String(record.address, radix: 16)
            let block: String
            if conflictingAddresses.contains(record.address) || conflictingNames.contains(Array(record.name.utf8)) {
                block = "// Ambiguous protocol reference at \(address): \(escaped(record.name)); no declaration selected.\n"
            } else if !declarationIdentifier(record.name) {
                block = "// Unsupported protocol name at \(address): \(escaped(record.name)).\n"
            } else {
                block = renderRecord(record, address: address)
            }
            guard block.utf8.count <= maximumOutputBytes - outputBytes else {
                // Atomic refusal avoids presenting a prefix as the complete captured record set.
                return heading + "// Protocol rendering unavailable: output exceeds bounded limits.\n"
            }
            outputBytes += block.utf8.count
            output += block
        }
        return output
    }

    // Swift String equality is canonically equivalent, not exact retained byte identity.
    // These local keys preserve every captured field without changing the retained model.
    // Constructed only after byte/member admission. These are in-memory keys, not provenance hashes.
    private struct MethodIdentity: Hashable {
        let selector: [UInt8]
        let encoding: [UInt8]?
        let isClassMethod: Bool
        let implementation: UInt64?
        init(_ method: ObjCMethod) {
            selector = Array(method.selector.utf8)
            encoding = method.typeEncoding.map { Array($0.utf8) }
            isClassMethod = method.isClassMethod
            implementation = method.implementation
        }
    }

    private struct PropertyIdentity: Hashable {
        let name: [UInt8]
        let attributes: [UInt8]
        init(_ property: ObjCProperty) {
            name = Array(property.name.utf8)
            attributes = Array(property.attributes.utf8)
        }
    }

    private struct RecordIdentity: Hashable {
        let name: [UInt8]
        let address: UInt64
        let inherited: [[UInt8]]
        let required: [MethodIdentity]
        let optional: [MethodIdentity]
        let properties: [PropertyIdentity]
        init(_ record: ObjCProtocol) {
            name = Array(record.name.utf8)
            address = record.address
            inherited = record.adoptedProtocols.map { Array($0.utf8) }
            required = record.requiredMethods.map { MethodIdentity($0) }
            optional = record.optionalMethods.map { MethodIdentity($0) }
            properties = record.properties.map { PropertyIdentity($0) }
        }
    }

    private static func admitted(_ records: [ObjCProtocol]) -> Bool {
        guard records.count <= maximumRecords else { return false }
        var members = 0
        var bytes = 0
        func charge(_ text: String) -> Bool {
            // Prefix inspection bounds work even for a single enormous captured string.
            let count = text.utf8.prefix(4_097).count
            guard count <= 4_096, count <= maximumInputBytes - bytes else { return false }
            bytes += count
            return true
        }
        for record in records {
            for count in [record.adoptedProtocols.count, record.requiredMethods.count,
                          record.optionalMethods.count, record.properties.count] {
                guard count <= maximumMembers - members else { return false }
                members += count
            }
            guard charge(record.name) else { return false }
            for name in record.adoptedProtocols where !charge(name) { return false }
            for methods in [record.requiredMethods, record.optionalMethods] {
                for method in methods {
                    guard charge(method.selector) else { return false }
                    if let encoding = method.typeEncoding, !charge(encoding) { return false }
                }
            }
            for property in record.properties {
                guard charge(property.name), charge(property.attributes) else { return false }
            }
        }
        return true
    }

    private static func renderRecord(_ record: ObjCProtocol, address: String) -> String {
        var lines = ["// Recovered descriptor \(address); inherited names are unresolved references."]
        if record.requiredMethods.isEmpty && record.optionalMethods.isEmpty && record.properties.isEmpty {
            lines.append("// No members were recovered for this descriptor; completeness unknown.")
        }
        // Comments precede @protocol so no property is placed under an asserted requirement mode.
        for property in record.properties {
            lines.append("// Property reference (requirement UNKNOWN; class/instance UNKNOWN): name=\(escaped(property.name)); attributes=\(escaped(property.attributes))")
        }
        var inherited: [String] = []
        for name in record.adoptedProtocols {
            if declarationIdentifier(name) { inherited.append(name) }
            else { lines.append("// Unsupported inherited reference: \(escaped(name))") }
        }
        let suffix = inherited.isEmpty ? "" : " <" + inherited.joined(separator: ", ") + ">"
        lines.append("@protocol \(record.name)\(suffix)")
        for (label, methods) in [("@required", record.requiredMethods), ("@optional", record.optionalMethods)] {
            guard !methods.isEmpty else { continue }
            lines.append(label)
            for method in methods {
                guard selector(method.selector), safeEncoding(method.typeEncoding) else {
                    lines.append("// Unsupported recovered method: \(escaped(method.selector)); type/selector display refused.")
                    continue
                }
                // implementation deliberately unused: a requirement never supplies a method body.
                lines.append(ObjCTypeEncoding.methodSignature(method))
            }
        }
        lines.append("@end\n")
        return lines.joined(separator: "\n")
    }

    private static func declarationIdentifier(_ text: String) -> Bool {
        let reserved: Set<String> = ["auto", "break", "case", "char", "const", "continue",
            "default", "do", "double", "else", "enum", "extern", "float", "for", "goto",
            "if", "inline", "int", "long", "register", "restrict", "return", "short",
            "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
            "unsigned", "void", "volatile", "while", "id", "Class", "SEL", "self", "super"]
        return identifier(text) && !reserved.contains(text)
    }

    private static func identifier(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        guard !bytes.isEmpty, bytes.count <= 128, initial(bytes[0]) else { return false }
        return bytes.dropFirst().allSatisfy { initial($0) || (48...57).contains($0) }
    }

    private static func initial(_ byte: UInt8) -> Bool {
        byte == 95 || (65...90).contains(byte) || (97...122).contains(byte)
    }

    private static func selector(_ text: String) -> Bool {
        guard text.utf8.count <= 512 else { return false }
        if !text.contains(":") { return identifier(text) }
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count <= 65 && parts.last?.isEmpty == true
            && parts.dropLast().allSatisfy { identifier(String($0)) }
    }

    /// Restrict only this display surface before invoking the existing best-effort decoder.
    /// Quoted class/field names and aggregate tags must be identifiers; bounded pointer/array
    /// recursion and ASCII encoding syntax cannot introduce source statements or comment breaks.
    private static func safeEncoding(_ encoding: String?) -> Bool {
        guard let encoding else { return true }
        guard encoding.utf8.count <= 256 else { return false }
        let bytes = Array(encoding.utf8)
        let punctuation = Array("@#:*^?=\"{}()[]+-".utf8)
        guard bytes.allSatisfy({ initial($0) || (48...57).contains($0) || punctuation.contains($0) }) else { return false }
        var i = 0
        while i < bytes.count {
            let byte = bytes[i]
            if byte == 34 {
                i += 1
                let start = i
                while i < bytes.count, bytes[i] != 34 { i += 1 }
                guard i < bytes.count, identifier(String(decoding: bytes[start..<i], as: UTF8.self)) else { return false }
            } else if byte == 123 || byte == 40 {
                let close: UInt8 = byte == 123 ? 125 : 41
                let start = i + 1
                var end = start
                while end < bytes.count, bytes[end] != 61, bytes[end] != close { end += 1 }
                guard end < bytes.count else { return false }
                let tag = String(decoding: bytes[start..<end], as: UTF8.self)
                guard tag.isEmpty || tag == "?" || identifier(tag) else { return false }
            }
            i += 1
        }
        return true
    }

    /// ASCII-only single-line comments. Encode slash, backslash and every nonprinting or
    /// non-ASCII scalar so neither comment termination nor Unicode line separators can escape.
    private static func escaped(_ text: String) -> String {
        var result = ""
        for scalar in text.unicodeScalars.prefix(160) {
            if scalar.value >= 32 && scalar.value <= 126 && scalar != "/" && scalar != "\\" {
                result.unicodeScalars.append(scalar)
            } else { result += "\\u{" + String(scalar.value, radix: 16) + "}" }
        }
        if text.unicodeScalars.dropFirst(160).first != nil { result += "...[truncated]" }
        return result
    }
}
