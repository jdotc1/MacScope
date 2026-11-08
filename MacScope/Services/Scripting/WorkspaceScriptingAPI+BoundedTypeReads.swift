import Foundation

extension WorkspaceScriptingAPI {
    /// Interpret an unpaged atlas limit without silently truncating or ignoring it.
    /// Callers retain their existing defaults and clamp at their original boundaries.
    nonisolated static func exactUnpagedAtlasLimit(_ arguments: ScriptValue) throws -> Int64? {
        guard let value = arguments["limit"], value != .null else { return nil }
        switch value {
        case .int(let value): return value
        case .double(let value):
            if let integer = Int64(exactly: value) { return integer }
        default: break
        }
        throw ScriptingError.invalidArgument("limit must be an exact integer in the Int64 range")
    }
    /// Shared preflight for analysis that hands user types to the synchronous ABI layout engine.
    nonisolated static func validateSnapshotTypeDefinitions(
        _ definitions: [TypeDefinition], checkpoint: () throws -> Void = {}
    ) throws {
        var budget = AttachedTypeReadBudget()
        try budget.definitions(definitions, includeLayout: true, checkpoint: checkpoint)
    }

    /// Attached reads preflight all preparation inputs before invoking the shared catalog builder.
    /// Its caches and reply projection stay authoritative. Oversized work is refused, rather than
    /// constructing an unbounded catalog and applying a row prefix afterwards.
    nonisolated static func snapshotTypeListRead(
        _ command: String, arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void = {}, swiftObjCLinks: Bool = true,
        mode: TypeAtlasUnpagedMode = .publicPrefix
    ) throws -> ScriptValue {
        if command == "list-image-types", let page = try typeAtlasPage(arguments, snapshot: snapshot,
            checkpoint: checkpoint, swiftObjCLinks: swiftObjCLinks) { return page }
        var budget = AttachedTypeReadBudget()
        try checkpoint()
        do {
            try budget.definitions(snapshot.typeDefinitions, includeLayout: command == "list-image-types",
                                   checkpoint: checkpoint)
        } catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
            throw budget.reportingRefusal(error)
        }
        if command == "list-types" {
            var rows: [ScriptValue] = []
            for definition in snapshot.typeDefinitions {
                try checkpoint()
                rows.append(.object([
                    "name": .string(definition.name), "kind": .string(definition.kind.rawValue),
                    "fields": .array(definition.fields.map {
                        .object(["name": .string($0.name), "type": .string($0.type)])
                    }),
                ]))
            }
            return .array(rows)
        }
        guard command == "list-image-types" else { throw ScriptingError.unknownCommand(command) }
        do {
            try budget.take(snapshot.binaries.count)
        } catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
            throw budget.reportingRefusal(error)
        }
        let slot = try resolveImageSlot(arguments, snapshot: snapshot)
        if let value = arguments["kind"], value != .null, value.stringValue == nil {
            throw ScriptingError.invalidArgument("kind must be a string")
        }
        let kind: TypeAtlasKind?
        if let text = arguments["kind"]?.stringValue {
            guard let parsed = TypeAtlasKind(rawValue: text) else {
                throw ScriptingError.invalidArgument(
                    "kind must be one of \(TypeAtlasKind.allCases.map(\.rawValue).joined(separator: "|"))")
            }
            kind = parsed
        } else { kind = nil }
        let catalog: ImageTypeCatalog
        let links: TypeAtlasSwiftObjCLinks
        do {
            try budget.take(snapshot.addressOverrides.count)
            for override in snapshot.addressOverrides.values {
                try checkpoint()
                try budget.text(override.appliedTypeName)
            }
            if let analysis = snapshot.analysisBySlot[slot] {
                if let catalog = analysis.typeCatalog {
                    try budget.entries(catalog.entries, checkpoint: checkpoint)
                } else {
                    try budget.analysis(analysis, checkpoint: checkpoint)
                }
            }
            try checkpoint()
            catalog = snapshot.typeCatalog(in: slot)
            try checkpoint()
            links = try swiftObjCLinks
                ? makeTypeAtlasSwiftObjCLinks(catalog.entries, checkpoint: checkpoint) : TypeAtlasSwiftObjCLinks()
        } catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
            guard try typeAtlasPageWouldPrepare(snapshot.analysisBySlot[slot], checkpoint: checkpoint) else {
                throw budget.reportingRefusal(.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "Type read exceeds the finite preparation or nested-result budget, and page mode cannot prepare this image either: its catalog is not cached and its derived user entries exceed 4194304; no argument narrows it.",
                    narrowing: [])))
            }
            throw budget.reportingRefusal(.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "Type read exceeds the finite preparation or nested-result budget; narrow the workspace type catalog. " + typeAtlasPageHint,
                narrowing: ["page"])))
        }
        let requested = try exactUnpagedAtlasLimit(arguments) ?? 5_000
        let limit = Int(max(0, min(requested, 5_000)))
        return try typeAtlasUnpagedReply(catalog.entries, links: links, slot: slot,
            snapshot: snapshot, kind: kind, limit: limit, mode: mode, checkpoint: checkpoint)
    }
}

/// Aggregate bounds, including nested collections and strings, apply before allocation. The
/// shared builder's cross-products also consume work credit; a row cap alone is insufficient.
struct AttachedTypeReadBudget {
    private static let nodeLimit = 4_096
    private static let byteLimit = 262_144
    private static let workLimit = 1_000_000
    private var nodes = Self.nodeLimit
    private var bytes = Self.byteLimit
    private var work = Self.workLimit

    mutating func take(_ count: Int) throws {
        guard count >= 0, count <= nodes else {
            throw recordRefusal(unit: .nodes, limit: Self.nodeLimit,
                used: count >= 0 ? Self.nodeLimit - nodes : nil, adding: count)
        }
        nodes -= count
    }

    mutating func charge(_ count: Int, times: Int = 1) throws {
        let (cost, overflow) = count.multipliedReportingOverflow(by: times)
        guard !overflow, cost >= 0, cost <= work else {
            throw recordRefusal(unit: .workSteps, limit: Self.workLimit,
                used: !overflow && cost >= 0 ? Self.workLimit - work : nil,
                adding: !overflow && cost >= 0 ? cost : 0)
        }
        work -= cost
    }

    mutating func text(_ value: String?) throws {
        guard let value else { return }
        // Bounded prefix counting avoids walking an arbitrarily large UTF-8 view.
        let count = value.utf8.prefix(2_049).count
        guard count <= 2_048 else {
            throw recordRefusal(unit: .bytes, limit: 2_048, used: count)
        }
        guard count <= bytes else {
            throw recordRefusal(unit: .bytes, limit: Self.byteLimit,
                used: Self.byteLimit - bytes, adding: count)
        }
        bytes -= count
    }

    /// Conservative fixed framing credit for the newly exposed fields, not a replacement for
    /// the transport's full escaped/serialized wrapper cap. Variable strings use text(_:).
    mutating func framing(_ count: Int) throws {
        guard count >= 0, count <= bytes else {
            throw recordRefusal(unit: .bytes, limit: Self.byteLimit,
                used: count >= 0 ? Self.byteLimit - bytes : nil, adding: count)
        }
        bytes -= count
    }

    mutating func swiftMetadata(_ value: SwiftMetadataMethod?) throws {
        guard value != nil else { try framing(24); return }
        try take(1) // The nested metadata object is additional to its already-counted method.
        try framing(320) // Six keys, enum, UInt64/UInt32 maxima, two addresses and nullable bool.
    }

    mutating func atlasMethod(_ value: TypeAtlasMethod, protocolRequirement: Bool,
                              swiftRecord: Bool, checkpoint: () throws -> Void) throws {
        try checkpoint()
        try text(value.name); try take(value.selectorUsers.count)
        if let category = value.category { try text(category) }
        if protocolRequirement { try framing(32) }
        if swiftRecord { try swiftMetadata(value.swiftMetadata) }
    }

    mutating func texts(_ values: [String]) throws {
        try take(values.count)
        for value in values { try text(value) }
    }

    mutating func definitions(_ values: [TypeDefinition], includeLayout: Bool,
                              checkpoint: () throws -> Void) throws {
        try checkpoint()
        try take(values.count)
        for definition in values {
            try checkpoint()
            try text(definition.name)
            try fields(definition.fields, depth: 0, checkpoint: checkpoint)
        }
        guard includeLayout else { return }
        // ABI layout revisits nested aliases/aggregates. Charge a conservative expansion
        // estimate before the existing synchronous layout engine receives the definitions.
        for definition in values {
            try layout(definition.fields, catalog: values, visiting: [definition.name],
                       multiplier: 1, checkpoint: checkpoint)
        }
    }

    mutating func fields(_ values: [FieldDef], depth: Int, checkpoint: () throws -> Void) throws {
        guard depth < 16 else {
            throw recordRefusal(unit: .nodes, limit: 16, used: depth, adding: 1)
        }
        try take(values.count)
        for value in values {
            try checkpoint()
            try text(value.name); try text(value.type); try text(value.minimumAlignmentType)
            try fields(value.inlineFields, depth: depth + 1, checkpoint: checkpoint)
        }
    }

    mutating func layout(_ fields: [FieldDef], catalog: [TypeDefinition], visiting: Set<String>,
                         multiplier: Int, checkpoint: () throws -> Void) throws {
        // Layout asks for size, alignment, atomic/bitfield rules and promoted members separately.
        // 64 credits per expansion deliberately overestimates these bounded repeated visits.
        try charge(fields.count, times: multiplier)
        for field in fields {
            try checkpoint()
            let (next, overflow) = multiplier.multipliedReportingOverflow(by: 64)
            guard !overflow else {
                throw recordRefusal(unit: .workSteps, limit: Self.workLimit, used: nil)
            }
            if !field.inlineFields.isEmpty {
                try layout(field.inlineFields, catalog: catalog, visiting: visiting,
                           multiplier: next, checkpoint: checkpoint)
            }
            for definition in catalog where !visiting.contains(definition.name) {
                try charge(1)
                // A conservative superset of the layout engine's exact aggregate/alias lookup.
                // False matches only refuse unusually complex input; no layout is fabricated.
                if field.type.contains(definition.name)
                    || field.minimumAlignmentType?.contains(definition.name) == true {
                    try layout(definition.fields, catalog: catalog, visiting: visiting.union([definition.name]),
                               multiplier: next, checkpoint: checkpoint)
                }
            }
        }
    }

    mutating func methods(_ values: [ObjCMethod]) throws {
        try take(values.count)
        for value in values { try text(value.selector) }
    }

    mutating func analysis(_ value: ImageAnalysis, checkpoint: () throws -> Void) throws {
        try take(value.objcClasses.count); try take(value.objcCategories.count)
        try take(value.objcProtocols.count); try take(value.swiftTypes.count)
        try take(value.swiftConformances.count); try take(value.xrefs.count)
        try take(value.objcSelectors.count); try take(value.objcClassReferences.count)
        var methodCount = 0
        for cls in value.objcClasses {
            try checkpoint()
            try text(cls.name); try text(cls.superclassName); try texts(cls.adoptedProtocols)
            try methods(cls.classMethods); try methods(cls.instanceMethods)
            methodCount += cls.classMethods.count + cls.instanceMethods.count
            try take(cls.ivars.count)
            for member in cls.ivars { try text(member.name); try text(member.typeEncoding) }
        }
        for category in value.objcCategories {
            try checkpoint()
            try text(category.name); try text(category.className); try texts(category.adoptedProtocols)
            try methods(category.classMethods); try methods(category.instanceMethods)
            methodCount += category.classMethods.count + category.instanceMethods.count
        }
        for proto in value.objcProtocols {
            try checkpoint()
            try text(proto.name); try texts(proto.adoptedProtocols)
            try framing(32) // declaredProperties, including unknown/empty framing
            try methods(proto.requiredMethods); try methods(proto.optionalMethods)
            for _ in proto.requiredMethods { try checkpoint(); try framing(32) }
            for _ in proto.optionalMethods { try checkpoint(); try framing(32) }
            methodCount += proto.requiredMethods.count + proto.optionalMethods.count
            try take(proto.properties.count)
            for property in proto.properties {
                try checkpoint(); try framing(40)
                try text(property.name); try text(property.attributes)
            }
        }
        var conformanceMethods = 0
        for conformance in value.swiftConformances {
            try checkpoint()
            try text(conformance.typeName); try text(conformance.protocolName)
            try framing(96)
            try take(conformance.methods?.count ?? 0)
            for method in conformance.methods ?? [] {
                try checkpoint(); try swiftMetadata(method); try text(method.label)
            }
            conformanceMethods += conformance.methods?.count ?? 0
        }
        for type in value.swiftTypes {
            try checkpoint()
            try text(type.name); try text(type.qualifiedName); try text(type.superclass)
            try framing(128) // New Swift row keys/array/table-resolution framing.
            try take(type.fields.count); try take(type.methods?.count ?? 0)
            for method in type.methods ?? [] {
                try checkpoint(); try swiftMetadata(method); try text(method.label)
            }
            for field in type.fields { try text(field.name); try text(field.typeName) }
        }
        for selector in value.objcSelectors.values { try checkpoint(); try text(selector) }
        for reference in value.objcClassReferences.values { try checkpoint(); try text(reference.name) }
        // Each method can inherit every selector user; each class can inherit every class user.
        try take((methodCount + value.objcClasses.count) * value.xrefs.count)
        try take(value.swiftTypes.count * (value.swiftConformances.count + conformanceMethods))
    }

    mutating func entries(_ values: [TypeAtlasEntry], checkpoint: () throws -> Void) throws {
        try take(values.count)
        for entry in values {
            try checkpoint()
            try text(entry.name); try text(entry.superclass)
            try WorkspaceScriptingAPI.visitImportedTypeText(in: entry) { try text($0) }
            try take(entry.members.count); try take(entry.users.count); try texts(entry.conformances)
            for member in entry.members { try text(member.name); try text(member.type) }
            try take(entry.methods.count)
            let swiftRecord: Bool
            switch entry.kind {
            case .swiftClass, .swiftStruct, .swiftEnum: swiftRecord = true
            default: swiftRecord = false
            }
            if swiftRecord { try framing(128) }
            if entry.kind == .objcProtocol { try framing(32) }
            for method in entry.methods {
                try atlasMethod(method, protocolRequirement: entry.kind == .objcProtocol,
                                swiftRecord: swiftRecord, checkpoint: checkpoint)
            }
            // Reuse existing collection charges; add only newly materialized metadata/framing.
            try take(entry.declaredProperties?.count ?? 0)
            for property in entry.declaredProperties ?? [] {
                try checkpoint()
                if entry.kind == .objcProtocol { try framing(40) }
                try text(property.name); try text(property.attributes)
            }
            try take(entry.swiftConformanceMethods?.count ?? 0)
            for conformance in entry.swiftConformanceMethods ?? [] {
                try checkpoint()
                if swiftRecord { try framing(96) }
                try text(conformance.protocolName)
                try take(conformance.methods?.count ?? 0)
                for method in conformance.methods ?? [] {
                    try atlasMethod(method, protocolRequirement: false,
                                    swiftRecord: swiftRecord, checkpoint: checkpoint)
                }
            }
        }
    }

    /// The original-entry preflight is intentionally conservative: it remains charged even
    /// when a Swift member list will be redirected. Account for every additive link value
    /// as well, including the repeated identity in membersListedOn and nullable field types.
    mutating func links(_ values: WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks,
                        checkpoint: () throws -> Void) throws {
        if values.counts != nil {
            try take(2) // swiftObjCLinks and its abstained object.
            try framing(256)
        }
        for link in values.byIndex.values {
            try checkpoint()
            try text(link.otherName)
            try take(1) // swiftId or objcId object
            try framing(160) // Link keys and fixed slot/kind/address identity fields.
            if case .name(let name) = link.otherID.key { try text(name) }
            if link.membersListedOn {
                try take(1)
                try framing(128)
                if case .name(let name) = link.otherID.key { try text(name) }
            }
            if let types = link.swiftFieldTypes {
                try take(types.count)
                for type in types {
                    try checkpoint()
                    try framing(24)
                    try text(type)
                }
            }
        }
    }

    private var refusedBudget: MCPRefusalBudget? = nil
    private var refusedUsed: Int64? = nil

    // Retain the existing sentinel so equality-based internal catches still match.
    // Diagnostics belong to this value, never to shared or request-global state.
    mutating func recordRefusal(unit: MCPRefusalBudget.Unit, limit: Int,
                               used: Int?, adding: Int = 0) -> ScriptingError {
        refusedBudget = .init(unit: unit, limit: Int64(limit))
        if let used {
            let (total, overflow) = used.addingReportingOverflow(adding)
            refusedUsed = overflow ? nil : Int64(exactly: total)
        } else {
            refusedUsed = nil
        }
        return Self.refused
    }

    // A caller supplies the already-selected detail/narrowing. Do not reinterpret it.
    func reportingRefusal(_ error: ScriptingError) -> ScriptingError {
        guard case .structuredRefusal(var refusal) = error,
              let refusedBudget else { return error }
        refusal.budget = refusedBudget
        refusal.used = refusedUsed
        return .structuredRefusal(refusal)
    }
    static var refused: ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "Type read exceeds the finite preparation or nested-result budget; narrow the workspace type catalog.",
            narrowing: []))
    }
}
