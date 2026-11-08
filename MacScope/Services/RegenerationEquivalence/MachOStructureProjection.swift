import Foundation

/// Static, address-independent facts only. Caller must parse both Mach-O inputs with metadata enabled.
enum MachOStructureProjection {
    private struct Facts {
        var records: [String: [StructuralRecord]] = [:]
        var available: [String: Bool] = [:]
        var recordCount = 0
        let budget: RegenerationWorkBudget
        let maximumRecords: Int
        mutating func add(_ dimension: String, _ parts: [String], _ value: String?) throws {
            try budget.checkpoint()
            guard recordCount < maximumRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            recordCount += 1
            let key = parts.map { "\($0.utf8.count):\($0)" }.joined()
            records[dimension, default: []].append(.init(key: key, value: value))
        }
    }

    static func compare(original: MachOFile, rebuilt: MachOFile, budget: RegenerationWorkBudget) throws -> [StructuralDimensionInput] {
        try budget.checkpoint()
        let a = try facts(original, budget: budget, maximumRecords: budget.maximumRecords)
        let b = try facts(rebuilt, budget: budget, maximumRecords: budget.maximumRecords - a.recordCount)
        try budget.checkpoint()
        let names = Set(a.available.keys).union(b.available.keys).sorted()
        return names.map { name in
            StructuralDimensionInput(name: name, original: a.records[name] ?? [], rebuilt: b.records[name] ?? [],
                                     available: a.available[name] == true && b.available[name] == true)
        }
    }

    private static func facts(_ image: MachOFile, budget: RegenerationWorkBudget, maximumRecords: Int) throws -> Facts {
        var f = Facts(budget: budget, maximumRecords: maximumRecords)
        // Empty diagnostics do not certify that parser-capped or skipped lists are complete.
        let objcOK = false
        let swiftOK = false
        let objcNames = ["Objective-C classes", "Objective-C superclasses", "Objective-C categories", "Objective-C protocols", "Objective-C adoption", "Objective-C methods", "Objective-C ivars", "Objective-C properties"]
        for n in objcNames { f.available[n] = objcOK }
        for n in ["Swift types", "Swift fields", "Swift enum cases"] { f.available[n] = swiftOK }
        f.available["Objective-C class flags"] = false
        f.available["Objective-C ivar offsets"] = false
        f.available["Objective-C ivar sizes"] = false
        f.available["Objective-C instance sizes"] = false
        f.available["Swift conformances"] = false
        f.available["Swift protocol requirements"] = false
        f.available["Swift generic signatures"] = false
        f.available["linked dylibs"] = true
        f.available["rpaths"] = true
        f.available["exports"] = image.exportRecoveryComplete
        // The merged view includes classic and chained imports, but the parser does not
        // currently certify completeness of every bind stream. Preserve observations unscored.
        f.available["imports"] = false
        for d in image.dylibs {
            let value = [d.loadKind, d.currentVersion.stringValue, d.compatibilityVersion.stringValue]
                .map { "\($0.utf8.count):\($0)" }.joined()
            try f.add("linked dylibs", [d.name], value)
        }
        for r in image.rpaths { try f.add("rpaths", [r.path], "present") }
        for e in image.exports { try f.add("exports", [e.name], "present") }
        for i in MachOLoadMetadata.from(image).importedSymbols {
            // Preserve the merged view's within-image ordinal, not raw chained encoding or cross-image identity.
            let detail = "reportedLibraryOrdinal=\(i.libraryOrdinal.map(String.init) ?? "unknown");weak=\(i.isWeak);addend=\(i.addend.map(String.init) ?? "unknown");source=\(i.source)"
            try f.add("imports", [i.libraryName ?? "<unresolved library>", i.name], detail)
        }
        func methods(_ values: [ObjCMethod], _ owner: [String], _ kind: String, _ into: inout Facts) throws {
            for method in values { try into.add("Objective-C methods", owner + [kind, method.isClassMethod ? "class" : "instance", method.selector], method.typeEncoding) }
        }
        func properties(_ values: [ObjCProperty], _ owner: [String], _ into: inout Facts) throws {
            for property in values { try into.add("Objective-C properties", owner + [property.name], property.attributes) }
        }
        for c in image.objectiveCMetadata.classes {
            let owner = ["class", c.name]
            try f.add("Objective-C classes", [c.name], "present")
            try f.add("Objective-C superclasses", [c.name], c.superclassName)
            // Retain captured layout scalars without claiming complete or runtime layout.
            try f.add("Objective-C instance sizes", owner, c.instanceSize.map { "staticInstanceByteCount=\($0)" })
            for item in c.adoptedProtocols { try f.add("Objective-C adoption", owner + [item], "present") }
            try methods(c.instanceMethods, owner, "instance", &f); try methods(c.classMethods, owner, "class", &f)
            for i in c.ivars {
                try f.add("Objective-C ivars", owner + [i.name], i.typeEncoding)
                try f.add("Objective-C ivar offsets", owner + [i.name], i.offset.map { "linkTimeByteOffset=\($0)" })
                try f.add("Objective-C ivar sizes", owner + [i.name], i.size.map { "staticByteCount=\($0)" })
            }
            try properties(c.properties, owner, &f)
        }
        for c in image.objectiveCMetadata.categories {
            let owner = ["category", c.className, c.name]
            try f.add("Objective-C categories", [c.className, c.name], "present")
            for item in c.adoptedProtocols { try f.add("Objective-C adoption", owner + [item], "present") }
            try methods(c.instanceMethods, owner, "instance", &f); try methods(c.classMethods, owner, "class", &f)
            try properties(c.properties, owner, &f)
        }
        for p in image.objectiveCMetadata.protocols {
            let owner = ["protocol", p.name]
            try f.add("Objective-C protocols", [p.name], "present")
            for item in p.adoptedProtocols { try f.add("Objective-C adoption", owner + [item], "present") }
            try methods(p.requiredMethods, owner, "required", &f); try methods(p.optionalMethods, owner, "optional", &f)
            try properties(p.properties, owner, &f)
        }
        for t in image.swiftTypes {
            try budget.checkpoint()
            let typeKey: [String]
            if let qualified = t.qualifiedName {
                typeKey = ["qualified", qualified]
                try f.add("Swift types", typeKey, t.kind.rawValue)
            } else {
                // Keep the short name as an observation, not a cross-image identity.
                typeKey = ["unqualified", t.name]
                try f.add("Swift types", typeKey, nil)
            }
            for field in t.fields {
                let dimension = t.kind.rawValue == "enum" ? "Swift enum cases" : "Swift fields"
                // The stored mangling may be sanitized and typeName may be unqualified.
                // Neither is a proven cross-image type identity.
                try f.add(dimension, typeKey + [field.name], nil)
            }
        }
        for c in image.swiftConformances {
            try budget.checkpoint()
            if let type = c.typeQualifiedName, let protocolName = c.protocolQualifiedName {
                try f.add("Swift conformances", ["qualified", type, protocolName], "present")
            } else {
                // Preserve partial observations without claiming a cross-image identity.
                try f.add("Swift conformances", ["unresolved",
                    c.typeQualifiedName == nil ? "missing" : "known", c.typeQualifiedName ?? "",
                    c.protocolQualifiedName == nil ? "missing" : "known", c.protocolQualifiedName ?? ""], nil)
            }
        }
        return f
    }
}
