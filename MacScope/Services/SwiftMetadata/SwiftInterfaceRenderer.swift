import Foundation

/// Pure same-image rendering. Identity admission does not infer a namespace or descriptor.
enum SwiftInterfaceRenderer {
    private enum Owner: Hashable {
        case nominal(Int)
        case qualifiedOrphan(String)
        case legacyOrphan(String)
    }

    private struct ProtocolIdentity: Hashable {
        let simple: String
        let qualified: String?
    }

    static func render(types: [SwiftTypeDescriptor], conformances: [SwiftConformance] = []) -> String {
        var descriptors: [UInt64: [Int]] = [:]
        var qualified: [String: [Int]] = [:]
        var simple: [String: [Int]] = [:]
        var qualifiedSimpleNames: [String: Set<String>] = [:]
        var protocolSimpleNames: [String: Set<String>] = [:]
        var descriptorSimpleNames: [UInt64: Set<String>] = [:]
        var descriptorQualifiers: [UInt64: Set<String>] = [:]
        var simpleQualifiers: [String: Set<String>] = [:]
        for (index, type) in types.enumerated() {
            simple[type.name, default: []].append(index)
            if let address = type.descriptorAddress {
                descriptors[address, default: []].append(index)
                descriptorSimpleNames[address, default: []].insert(type.name)
                if let name = type.qualifiedName { descriptorQualifiers[address, default: []].insert(name) }
            }
            if let name = type.qualifiedName {
                qualified[name, default: []].append(index)
                qualifiedSimpleNames[name, default: []].insert(type.name)
                simpleQualifiers[type.name, default: []].insert(name)
            }
        }
        // Contradictory retained claims are considered before any output is assigned.
        for conformance in conformances {
            if let address = conformance.typeDescriptorAddress {
                descriptorSimpleNames[address, default: []].insert(conformance.typeName)
            }
            if let name = conformance.protocolQualifiedName {
                protocolSimpleNames[name, default: []].insert(conformance.protocolName)
            }
            if let name = conformance.typeQualifiedName {
                simpleQualifiers[conformance.typeName, default: []].insert(name)
                qualifiedSimpleNames[name, default: []].insert(conformance.typeName)
                if let address = conformance.typeDescriptorAddress {
                    descriptorQualifiers[address, default: []].insert(name)
                }
            }
        }
        var protocols: [Owner: [String]] = [:]
        var seenProtocols: [Owner: Set<ProtocolIdentity>] = [:]
        var orphanOrder: [Owner] = []
        var diagnostics: [String] = []
        var seenDiagnostics: Set<String> = []

        func diagnostic(_ conformance: SwiftConformance, _ reason: String) -> String {
            let address = conformance.typeDescriptorAddress.map { "0x" + String($0, radix: 16) } ?? "absent"
            return "// Unresolved Swift conformance (\(reason)): type=\(commentText(conformance.typeName)); qualified=\(conformance.typeQualifiedName.map(commentText) ?? "<absent>"); descriptor=\(address); protocol=\(commentText(conformance.protocolName)); protocolQualified=\(conformance.protocolQualifiedName.map(commentText) ?? "<absent>")"
        }
        func nominalConflict(_ index: Int, _ conformance: SwiftConformance) -> Bool {
            let type = types[index]
            if type.name != conformance.typeName { return true }
            if let name = type.qualifiedName, (qualifiedSimpleNames[name]?.count ?? 0) > 1 { return true }
            if let address = type.descriptorAddress {
                if descriptors[address]?.count != 1 || (descriptorQualifiers[address]?.count ?? 0) > 1 || (descriptorSimpleNames[address]?.count ?? 0) > 1 { return true }
            }
            if let name = conformance.typeQualifiedName, let owners = qualified[name],
               owners.count != 1 || owners.first != index { return true }
            if let left = type.qualifiedName, let right = conformance.typeQualifiedName, left != right { return true }
            return false
        }
        for conformance in conformances {
            var owner: Owner?
            var refusal = "ambiguous or conflicting identity"
            if let address = conformance.typeDescriptorAddress {
                if let candidates = descriptors[address], candidates.count == 1,
                   let index = candidates.first, !nominalConflict(index, conformance) {
                    owner = .nominal(index)
                } else if descriptors[address] == nil {
                    refusal = "unresolved local descriptor"
                }
            } else if let name = conformance.typeQualifiedName {
                if let candidates = qualified[name] {
                    if candidates.count == 1, let index = candidates.first, !nominalConflict(index, conformance) {
                        owner = .nominal(index)
                    }
                } else {
                    // Retained external qualification is its own identity, never a simple-name join.
                    owner = .qualifiedOrphan(name)
                }
            } else if (simpleQualifiers[conformance.typeName]?.count ?? 0) <= 1 {
                if let candidates = simple[conformance.typeName] {
                    if candidates.count == 1, let index = candidates.first, !nominalConflict(index, conformance) {
                        owner = .nominal(index)
                    }
                } else {
                    owner = .legacyOrphan(conformance.typeName)
                }
            }
            if let name = conformance.typeQualifiedName, (qualifiedSimpleNames[name]?.count ?? 0) > 1 {
                owner = nil
            }
            if let name = conformance.protocolQualifiedName, (protocolSimpleNames[name]?.count ?? 0) > 1 {
                owner = nil; refusal = "conflicting protocol identity"
            }
            let protocolText = conformance.protocolQualifiedName ?? conformance.protocolName
            let protocolDisplay = conformance.protocolQualifiedName == nil
                ? SwiftInterfaceLexical.identifier(protocolText) : SwiftInterfaceLexical.path(protocolText)
            if !isSourcePath(protocolText) || protocolDisplay == nil { owner = nil; refusal = "unnameable protocol evidence" }
            if let selected = owner {
                switch selected {
                case .qualifiedOrphan(let name):
                    if !isSourcePath(name) || SwiftInterfaceLexical.path(name) == nil { owner = nil; refusal = "unnameable orphan evidence" }
                case .legacyOrphan(let name):
                    if !isSourcePath(name) || SwiftInterfaceLexical.identifier(name) == nil { owner = nil; refusal = "unnameable orphan evidence" }
                case .nominal: break
                }
            }
            guard let owner else {
                let text = diagnostic(conformance, refusal)
                if seenDiagnostics.insert(text).inserted { diagnostics.append(text) }
                continue
            }
            let identity = ProtocolIdentity(simple: conformance.protocolName, qualified: conformance.protocolQualifiedName)
            guard seenProtocols[owner, default: []].insert(identity).inserted else { continue }
            if protocols[owner] == nil {
                switch owner {
                case .nominal: break
                case .qualifiedOrphan, .legacyOrphan: orphanOrder.append(owner)
                }
            }
            protocols[owner, default: []].append(protocolText)
        }
        var blocks = types.enumerated().map { index, type in
            renderType(type, conformances: protocols[.nominal(index)] ?? [])
        }
        for owner in orphanOrder {
            switch owner {
            case .qualifiedOrphan(let name), .legacyOrphan(let name):
                // Raw ownership is retained; only the lexically admitted display is escaped.
                if let display = SwiftInterfaceLexical.path(name) {
                    blocks.append("extension \(display): \((protocols[owner] ?? []).compactMap(SwiftInterfaceLexical.path).joined(separator: ", ")) {}")
                }
            case .nominal: break
            }
        }
        blocks.append(contentsOf: diagnostics)
        return blocks.joined(separator: "\n\n")
    }

    /// Only recovered name paths can form new inheritance/extension syntax. Manglings and
    /// diagnostic context markers remain visible in comments; they are not cleaned into names.
    private static func isSourcePath(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        return !parts.isEmpty && parts.allSatisfy { part in
            guard let first = part.unicodeScalars.first,
                  first == "_" || CharacterSet.letters.contains(first) else { return false }
            return part.unicodeScalars.allSatisfy {
                $0 == "_" || CharacterSet.alphanumerics.contains($0)
            }
        }
    }

    /// One line per diagnostic, with reversible scalar escapes; no truncation or name rewriting.
    private static func commentText(_ text: String) -> String {
        SwiftInterfaceLexical.comment(text)
    }

    private static func renderType(_ type: SwiftTypeDescriptor, conformances: [String] = []) -> String {
        guard let name = SwiftInterfaceLexical.identifier(type.name) else {
            // No substitute owner: its members remain evidence, never detached declarations.
            var lines = ["// Unrenderable Swift type: name=\(commentText(type.name)); kind=\(type.kind.rawValue); rawKind=\(type.rawKind.map(String.init) ?? "?")"]
            lines += type.fields.map { "// Retained member: name=\(commentText($0.name)); type=\($0.typeName.map(commentText) ?? "<absent>"); indirect=\($0.isIndirectCase)" }
            lines += conformances.map { "// Retained conformance: \(commentText($0))" }
            return lines.joined(separator: "\n")
        }
        var declaration = type.kind == .unknown
            ? "/* Swift type with kind \(type.rawKind.map(String.init) ?? "?") */ \(name)"
            : "\(type.kind.keyword) \(name)"
        if !conformances.isEmpty {
            declaration += ": \(conformances.compactMap(SwiftInterfaceLexical.path).joined(separator: ", "))"
        }
        var lines = ["\(declaration) {"]
        for field in type.fields {
            lines.append("    " + renderMember(field, in: type.kind))
        }
        lines.append("}")
        return lines.joined(separator: "\n")
    }

    private static func renderMember(_ field: SwiftField, in kind: SwiftTypeKind) -> String {
        guard let name = SwiftInterfaceLexical.identifier(field.name) else {
            return "// Unrenderable Swift member: name=\(commentText(field.name)); type=\(field.typeName.map(commentText) ?? "<absent>"); indirect=\(field.isIndirectCase)"
        }
        let type = field.typeName.flatMap(SwiftInterfaceLexical.typeDisplay)
        let refusal: String
        if let raw = field.typeName, type == nil {
            refusal = " // Unrenderable type: \(commentText(raw))"
        } else { refusal = "" }
        if kind == .enum {
            let keyword = field.isIndirectCase ? "indirect case" : "case"
            if let type {
                return "\(keyword) \(name)(\(type))" + refusal
            }
            return "\(keyword) \(name)" + refusal
        }
        let binding = field.isVar ? "var" : "let"
        return "\(binding) \(name)" + (type.map { ": \($0)" } ?? "") + refusal
    }
}
