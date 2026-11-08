import Foundation

/// Resolves call ABI from DIE tags and widths; display spellings never confer ABI authority.
struct NativeFunctionPrototypeResolver {
    private let roots: [DWARFDIENode]

    init(sections: DWARFReader.Sections) { roots = DWARFDIETree(sections: sections).parse() }
    init(roots: [DWARFDIENode]) { self.roots = roots }

    func resolve() -> [UInt64: NativeFunctionPrototypeEvidence] {
        var result: [UInt64: NativeFunctionPrototypeEvidence] = [:]
        var conflicts = Set<UInt64>()
        for root in roots {
            var nodes: [DWARFDIENode] = []
            func walk(_ node: DWARFDIENode) { nodes.append(node); node.children.forEach(walk) }
            walk(root)
            let pairs = nodes.compactMap { node in node.cuOffset.map { ($0, node) } }
            let groups = Dictionary(grouping: pairs, by: \.0)
            let map = groups.compactMapValues { values in values.count == 1 ? values[0].1 : nil }
            let language = number(root.attributes[0x13])
            for node in nodes where node.tag == DWARFConstants.tagSubprogram {
                guard case .address(let address)? = node.attributes[DWARFConstants.atLowPC],
                      !conflicts.contains(address) else { continue }
                let evidence = declaration(node, language: language, map: map)
                if let prior = result[address], prior != evidence {
                    conflicts.insert(address)
                    result[address] = .ineligible("Conflicting DWARF call declarations.")
                } else { result[address] = evidence }
            }
        }
        return result
    }

    private func declaration(_ node: DWARFDIENode, language: UInt64?, map: [Int: DWARFDIENode]) -> NativeFunctionPrototypeEvidence {
        guard let sources = sources(node, map: map) else {
            return .ineligible("The DWARF declaration contains unresolved or cyclic references.")
        }
        // DW_LANG_ObjC, ObjC++, Swift. A user signature cannot change the calling convention.
        if let language, [UInt64(0x10), 0x11, 0x1e].contains(language) {
            return .ineligible("Objective-C and Swift calls are not supported in this release.")
        }
        if sources.contains(where: { number($0.attributes[0x36]).map { $0 != 1 } ?? false })
            || sources.contains(where: { $0.attributes[0x64] != nil || number($0.attributes[0x3fee]) == 1 }) {
            return .ineligible("This function requires an unsupported or hidden calling convention.")
        }
        let parameterOwners = sources.filter { $0.children.contains { $0.tag == DWARFConstants.tagFormalParameter || $0.tag == 0x18 } }
        guard parameterOwners.count <= 1 else {
            return .ineligible("Multiple DWARF parameter lists require review.")
        }
        let children = parameterOwners.first?.children ?? []
        if children.contains(where: { $0.tag == 0x18 }) { return .ineligible("Variadic calls are not supported.") }
        let parameters = children.filter { $0.tag == DWARFConstants.tagFormalParameter }
        if parameters.contains(where: { number($0.attributes[0x34]).map { $0 != 0 } ?? false }) {
            return .ineligible("The function has hidden or artificial parameters.")
        }
        guard !parameters.isEmpty || sources.contains(where: { number($0.attributes[DWARFConstants.atPrototyped]) == 1 }) else {
            return .needsExplicitSignature("DWARF does not establish a complete parameter list.")
        }
        let returnAttribute = sources.lazy.compactMap { $0.attributes[DWARFConstants.atType] }.first
        let returnType: NativeFunctionScalarType
        if let returnAttribute {
            guard let value = scalar(returnAttribute, map: map, visited: []) else {
                return .ineligible("The DWARF return type is outside the supported integer/pointer ABI.")
            }
            returnType = value
        } else { returnType = .void }
        var types: [NativeFunctionScalarType] = []
        for parameter in parameters {
            guard let values = self.sources(parameter, map: map),
                  let reference = values.lazy.compactMap({ $0.attributes[DWARFConstants.atType] }).first,
                  let type = scalar(reference, map: map, visited: []), type != .void else {
                return .ineligible("A DWARF parameter has an unsupported or unresolved ABI type.")
            }
            types.append(type)
        }
        guard let prototype = try? NativeFunctionPrototype(returnType: returnType, parameterTypes: types, provenance: .authoritativeDWARF) else {
            return .ineligible("The parameter list exceeds the native-call limit.")
        }
        return .authoritative(prototype)
    }

    private func sources(_ first: DWARFDIENode, map: [Int: DWARFDIENode]) -> [DWARFDIENode]? {
        var values: [DWARFDIENode] = []
        var visited = Set<Int>()
        func visit(_ node: DWARFDIENode, depth: Int) -> Bool {
            guard depth < 32 else { return false }
            if let offset = node.cuOffset, !visited.insert(offset).inserted { return false }
            values.append(node)
            for key in [DWARFConstants.atSpecification, DWARFConstants.atAbstractOrigin] {
                if let attribute = node.attributes[key] {
                    guard let raw = number(attribute), let offset = Int(exactly: raw),
                          let source = map[offset], visit(source, depth: depth + 1) else { return false }
                }
            }
            return true
        }
        return visit(first, depth: 0) ? values : nil
    }

    private func scalar(_ reference: DWARFAttributeValue, map: [Int: DWARFDIENode], visited: Set<Int>) -> NativeFunctionScalarType? {
        guard let raw = number(reference), let offset = Int(exactly: raw),
              !visited.contains(offset), visited.count < 32, let node = map[offset] else { return nil }
        let visited = visited.union([offset])
        switch node.tag {
        case DWARFConstants.tagTypedef, DWARFConstants.tagConstType, DWARFConstants.tagVolatileType, DWARFConstants.tagRestrictType:
            guard let type = node.attributes[DWARFConstants.atType] else { return nil }
            return scalar(type, map: map, visited: visited)
        case DWARFConstants.tagPointerType:
            guard number(node.attributes[DWARFConstants.atByteSize]).map({ $0 == 8 }) ?? true else { return nil }
            return .pointer
        case DWARFConstants.tagBaseType:
            guard let size = number(node.attributes[DWARFConstants.atByteSize]), [1, 2, 4, 8].contains(size),
                  let encoding = number(node.attributes[0x3e]) else { return nil }
            let signed: Bool
            switch encoding { case 5, 6: signed = true; case 7, 8: signed = false; default: return nil }
            switch (size, signed) {
            case (1, true): return .int8
            case (1, false): return .uint8
            case (2, true): return .int16
            case (2, false): return .uint16
            case (4, true): return .int32
            case (4, false): return .uint32
            case (8, true): return .int64
            case (8, false): return .uint64
            default: return nil
            }
        default: return nil
        }
    }

    private func number(_ value: DWARFAttributeValue?) -> UInt64? {
        switch value { case .uint(let number)?: number; case .sint(let number)? where number >= 0: UInt64(number); default: nil }
    }
}
