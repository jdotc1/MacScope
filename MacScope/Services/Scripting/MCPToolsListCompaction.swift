/// Value-only listing transformation; no store, registry, or authority access.
enum MCPToolsListCompaction: Sendable {
    // Frozen at the packet pin. Exact string matching fails safe on source drift.
    // MCPServer.swift:826 (part2of4).
    static let generationDescription = "Optional analysis generation from the reply's generation text block (also result._meta.generation); null or omission retains legacy unconditional writes. A mismatch is staleEvidence with basedOnGeneration and currentGeneration."
    // MCPServer.swift:1065 (part2of4).
    static let addressDescription = "Unsigned address. Exact-address tools use the address itself. Function-selector tools require a containing function (or the exact start of a zero-width function) and refuse uncovered addresses; a supplied function name takes precedence. Prefer a hexadecimal string to preserve all 64 bits."
    // MCPServer.swift:1086 (part2of4).
    static let rowImageDescription = "Restrict the rows to one loaded image: a slot index or an image-owner ID (UUID). Omit to search every image (search) or read the primary image (callers, callees, xrefs, function-references). Every row reports the `imageSlot` that produced it."
    // MCPServer.swift:1094 (part2of4).
    static let primaryImageDescription = "Image to read: a slot index (0 is the primary image) or an image-owner ID (UUID). Omit for the primary image."
    static let canonicalDescriptions = [
        generationDescription, addressDescription, rowImageDescription,
        primaryImageDescription,
    ]
    private static let removableDescriptions = Set(canonicalDescriptions)
    // WorkspaceScriptingAPI.swift:182 (part1of8), including its leading space.
    static let evidenceAppendage = " Optional basedOnGeneration is an analysis-generation UUID from prior evidence; a mismatch refuses the write with staleEvidence and both generations. MCP write replies disclose the resulting generation; guarded object replies also include generation."
    static let mutationMarker = " (mutates the workspace)"
    private static let coreMutators: Set<String> = ["rename", "set-names", "set-comment", "set-comments"]

    static func entry(_ entry: ScriptValue, profile: MCPToolListingProfile?) -> ScriptValue {
        guard profile == .core, case .object(var fields) = entry else { return entry }
        if case .object(var schema) = fields["inputSchema"],
           case .object(var properties) = schema["properties"] {
            for (name, value) in properties {
                guard case .object(var property) = value,
                      let description = property["description"]?.stringValue,
                      removableDescriptions.contains(description) else { continue }
                property.removeValue(forKey: "description")
                properties[name] = .object(property)
            }
            schema["properties"] = .object(properties)
            fields["inputSchema"] = .object(schema)
        }
        if let name = fields["name"]?.stringValue, coreMutators.contains(name),
           let description = fields["description"]?.stringValue,
           description.hasSuffix(evidenceAppendage + mutationMarker) {
            fields["description"] = .string(
                String(description.dropLast((evidenceAppendage + mutationMarker).count)) + mutationMarker
            )
        }
        return .object(fields)
    }

    static func instructionSupplement(for profile: MCPToolListingProfile?) -> String {
        guard let profile else { return "" }
        let opening: String
        switch profile {
        case .core:
            opening = "tools/list is using core: 24 read tools plus rename, set-names, set-comment and set-comments."
        case .full:
            opening = "tools/list is using full. Core contains 24 read tools plus rename, set-names, set-comment and set-comments."
        }
        let schemaAdvice: String
        switch profile {
        case .core: schemaAdvice = "For other allowed schemas, launch with MACSCOPE_MCP_LIST_PROFILE=full and reconnect."
        case .full: schemaAdvice = "To return to the compact listing, launch with MACSCOPE_MCP_LIST_PROFILE=core and reconnect."
        }
        let guidance = opening + " Those four mutate the workspace and keep their call authority and mutation annotations. " + schemaAdvice + " An absent setting selects core; unknown values select full with one stderr warning. Request parameters never select a profile. Fixed-list clients need a fresh full listing for hidden tools; commands lists scripting names, not every MCP schema. MACSCOPE_MCP_HARNESS_TOOLS=1 independently controls harness visibility."
        guard profile == .core else { return "\n" + guidance }
        return "\n" + ([guidance] + canonicalDescriptions + [evidenceAppendage]).joined(separator: "\n")
    }
}
