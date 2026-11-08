import Foundation

struct TypeAtlasSwiftObjCLinkCounts: Equatable, Sendable {
    var linked = 0
    var membersNotMerged = 0
    var runtimeNameUndecodable = 0
    var noSwiftRow = 0
    var ambiguous = 0
    var privateOrLocal = 0
    var generic = 0
}

extension WorkspaceScriptingAPI {
    struct TypeAtlasSwiftObjCLink: Sendable {
        var isObjC: Bool
        var otherName: String
        var otherID: TypeAtlasEntryID
        var swiftFieldTypes: [String?]? = nil
        var membersListedOn = false
    }

    struct TypeAtlasSwiftObjCLinks: Sendable {
        var byIndex: [Int: TypeAtlasSwiftObjCLink] = [:]
        var counts: TypeAtlasSwiftObjCLinkCounts? = nil
    }

    /// Population: objcClass rows starting with _Tt, counted once in this order:
    /// undecodable, no Swift class, ambiguous name or row identity, private/local, generic, linked.
    /// linked + the five abstentions equals the population; membersNotMerged is a linked subset.
    /// Share only unique matching names whose known Swift layout survives on the ObjC row; a Swift member
    /// with no layout fact (no offset, size or imported identity, evidence unknown) merges into its ObjC member.
    /// Identity and counts use the whole slot catalog, before any request filter or prefix.
    nonisolated static func makeTypeAtlasSwiftObjCLinks(
        _ entries: [TypeAtlasEntry], checkpoint: () throws -> Void
    ) throws -> TypeAtlasSwiftObjCLinks {
        var swiftByName: [String: [Int]] = [:]
        var objcByName: [String: Int] = [:]
        var decoded: [Int: String] = [:]
        var population: [Int] = []
        // Count every retained identity, not just the _Tt population: fallback
        // Swift names, duplicate descriptors and non-_Tt ObjC rows can otherwise
        // make a serialized link name more than one row.
        var identityCounts: [TypeAtlasEntryID: Int] = [:]
        for (index, entry) in entries.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            identityCounts[entry.id, default: 0] += 1
            if entry.kind == .swiftClass, let name = entry.qualifiedName {
                swiftByName[name, default: []].append(index)
            }
            if entry.kind == .objcClass, entry.name.hasPrefix("_Tt") {
                population.append(index)
                if let name = SwiftDemangler.demangleLegacyClassName(entry.name) {
                    decoded[index] = name
                    objcByName[name, default: 0] += 1
                }
            }
        }
        guard !population.isEmpty else { return TypeAtlasSwiftObjCLinks() }
        var result = TypeAtlasSwiftObjCLinks()
        var counts = TypeAtlasSwiftObjCLinkCounts()
        for (ordinal, index) in population.enumerated() {
            if ordinal % checkpointInterval == 0 { try checkpoint() }
            guard let name = decoded[index] else { counts.runtimeNameUndecodable += 1; continue }
            guard let candidates = swiftByName[name], !candidates.isEmpty else {
                counts.noSwiftRow += 1; continue
            }
            guard candidates.count == 1, objcByName[name] == 1 else { counts.ambiguous += 1; continue }
            let swiftIndex = candidates[0]
            let objc = entries[index], swift = entries[swiftIndex]
            // Identity ambiguity precedes privacy/generic abstentions, like name ambiguity.
            guard identityCounts[objc.id] == 1, identityCounts[swift.id] == 1,
                  objc.id.slot == swift.id.slot else { counts.ambiguous += 1; continue }
            guard swift.isPrivateOrLocal == false else { counts.privateOrLocal += 1; continue }
            guard swift.isGeneric == false else { counts.generic += 1; continue }
            var canShareMembers = objc.members.count == swift.members.count
            if canShareMembers {
                var seenNames = Set<String>()
                for memberIndex in objc.members.indices {
                    if memberIndex % checkpointInterval == 0 { try checkpoint() }
                    let objcMember = objc.members[memberIndex]
                    let swiftMember = swift.members[memberIndex]
                    guard !swiftMember.name.isEmpty, objcMember.name == swiftMember.name,
                          seenNames.insert(swiftMember.name).inserted else {
                        canShareMembers = false; break
                    }
                    // Swift type is copied, but a Swift layout value must not be
                    // hidden if the remaining ObjC row lacks it or disagrees.
                    if let offset = swiftMember.offset, objcMember.offset != offset {
                        canShareMembers = false; break
                    }
                    if let size = swiftMember.size, objcMember.size != size {
                        canShareMembers = false; break
                    }
                    // The remaining row must also retain the Swift member's provenance
                    // and any imported field identity, not merely its display values.
                    // A Swift member that carries no layout fact hides nothing: only its name and type exist.
                    let swiftHasNoLayout = swiftMember.offset == nil && swiftMember.size == nil
                        && swiftMember.imported == nil && swiftMember.evidence == .unknown
                    if !swiftHasNoLayout, objcMember.evidence != swiftMember.evidence ||
                        (swiftMember.imported != nil && objcMember.imported != swiftMember.imported) {
                        canShareMembers = false; break
                    }
                }
            }
            let mergeMembers = canShareMembers && !objc.members.isEmpty
            var types: [String?]?
            if mergeMembers {
                var values: [String?] = []
                values.reserveCapacity(swift.members.count)
                for (memberIndex, member) in swift.members.enumerated() {
                    if memberIndex % checkpointInterval == 0 { try checkpoint() }
                    values.append(member.type)
                }
                types = values
            }
            counts.linked += 1
            if !canShareMembers { counts.membersNotMerged += 1 }
            // Equality may be canonically equivalent; emit the stored Swift spelling.
            result.byIndex[index] = TypeAtlasSwiftObjCLink(isObjC: true, otherName: swift.qualifiedName ?? name,
                otherID: swift.id, swiftFieldTypes: types)
            result.byIndex[swiftIndex] = TypeAtlasSwiftObjCLink(isObjC: false, otherName: objc.name,
                otherID: objc.id, membersListedOn: mergeMembers)
        }
        try checkpoint()
        result.counts = counts
        return result
    }

    nonisolated static func typeAtlasLinkCountsValue(_ counts: TypeAtlasSwiftObjCLinkCounts) -> ScriptValue {
        .object(["linked": .int(Int64(counts.linked)), "membersNotMerged": .int(Int64(counts.membersNotMerged)),
            "abstained": .object([
                "runtimeNameUndecodable": .int(Int64(counts.runtimeNameUndecodable)),
                "noSwiftRow": .int(Int64(counts.noSwiftRow)), "ambiguous": .int(Int64(counts.ambiguous)),
                "privateOrLocal": .int(Int64(counts.privateOrLocal)), "generic": .int(Int64(counts.generic)),
            ])])
    }

    private nonisolated static func typeAtlasLinkIDValue(_ id: TypeAtlasEntryID) -> ScriptValue {
        var fields: [String: ScriptValue] = ["slot": .int(Int64(id.slot.rawValue)), "kind": .string(id.kind.rawValue)]
        switch id.key {
        case .address(let address): fields["address"] = .hex(address)
        case .name(let name): fields["name"] = .string(name)
        }
        return .object(fields)
    }

    nonisolated static func applyingTypeAtlasLink(
        _ row: ScriptValue, link: TypeAtlasSwiftObjCLink?, namesOnly: Bool = false,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        guard let link, case .object(var fields) = row else { return row }
        let key = link.isObjC ? "swiftName" : "objcName"
        if namesOnly {
            let text = link.otherName
            let cap = maximumListPageFieldBytes / 2
            // Bound only application-level traversal; String internals are outside this budget.
            let admissionLimit = 16_384
            var prefix = "", prefixBytes = 0, length = 0, scalarCount = 0
            var truncated = false
            try checkpoint()
            for scalar in text.unicodeScalars {
                if scalarCount > 0 && scalarCount.isMultiple(of: checkpointInterval) { try checkpoint() }
                let width = scalar.value <= 0x7f ? 1 : scalar.value <= 0x7ff ? 2 : scalar.value <= 0xffff ? 3 : 4
                guard width <= admissionLimit - length else {
                    try checkpoint()
                    throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                        detail: "Type Atlas linked-name projection exceeds 16384 UTF-8 bytes; used is an observed prefix, not the full length.",
                        field: key, budget: .init(unit: .bytes, limit: Int64(admissionLimit)),
                        used: Int64(length + width), narrowing: []))
                }
                length += width
                scalarCount += 1
                if !truncated {
                    if width <= cap - prefixBytes {
                        prefix.unicodeScalars.append(scalar)
                        prefixBytes += width
                    } else { truncated = true }
                }
            }
            try checkpoint()
            if truncated {
                fields[key] = .string(prefix)
                fields[key + "Truncated"] = .bool(true)
                fields[key + "ByteLength"] = .int(Int64(length))
            } else { fields[key] = .string(text) }
            return .object(fields)
        }
        fields[key] = .string(link.otherName)
        let identity = typeAtlasLinkIDValue(link.otherID)
        fields[link.isObjC ? "swiftId" : "objcId"] = identity
        if link.isObjC, let types = link.swiftFieldTypes,
           let value = fields["members"], case .array(var members) = value, members.count == types.count {
            for index in members.indices {
                if index % checkpointInterval == 0 { try checkpoint() }
                if case .object(var member) = members[index] {
                    member["swiftFieldType"] = types[index].map(ScriptValue.string) ?? .null
                    members[index] = .object(member)
                }
            }
            fields["members"] = .array(members)
        } else if link.membersListedOn {
            fields["members"] = .array([])
            fields["membersListedOn"] = identity
        }
        return .object(fields)
    }
}
