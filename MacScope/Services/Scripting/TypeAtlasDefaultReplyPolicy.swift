import Foundation

let defaultTypeAtlasEscapedRowCap = 166_000

/// Internal policy only; no command argument is converted to this enum.
enum TypeAtlasUnpagedMode: Equatable {
    case publicPrefix
    case internalComplete
}

enum TypeAtlasDefaultReplyPolicy {
    /// The model preserves the implementation-symbol evidence that is absent from JSON.
    /// Never summarize a symbol-derived name, even if it resembles a positional label.
    static func summarized(
        _ entry: TypeAtlasEntry, checkpoint: () throws -> Void
    ) throws -> (entry: TypeAtlasEntry, slots: Int) {
        switch entry.kind {
        case .swiftClass, .swiftStruct, .swiftEnum: break
        default: return (entry, 0)
        }
        var removed = Set<UInt64>()
        var retained: [TypeAtlasMethod] = []
        for method in entry.methods {
            try checkpoint()
            if let metadata = method.swiftMetadata, metadata.source == .vtable,
               metadata.implementationSymbol == nil,
               method.name == "vtable #\(metadata.index) (name unknown)" {
                guard removed.insert(metadata.index).inserted else { return (entry, 0) }
            } else {
                retained.append(method)
            }
        }
        guard !removed.isEmpty, removed.min() == 0,
              removed.max() == UInt64(removed.count - 1) else { return (entry, 0) }
        var result = entry
        result.methods = retained
        return (result, removed.count)
    }

    // Only newly covered caller exits opt in; the shared sentinel is never changed.
    static let observedPrefixNote = "used is an observed prefix, not the full count. "

    static func labelPrefix(_ error: ScriptingError) -> ScriptingError {
        guard case .structuredRefusal(var refusal) = error else { return error }
        // Keep the label inside executionRefusal's first 1,024 characters.
        refusal.detail = observedPrefixNote + refusal.detail
        return .structuredRefusal(refusal)
    }

    static func labelBudgetPrefix(_ error: ScriptingError) -> ScriptingError {
        guard case .structuredRefusal(let refusal) = error,
              refusal.budget == MCPRefusalBudget(unit: .bytes, limit: 2_048),
              refusal.used == 2_049 else { return error }
        return labelPrefix(error)
    }

    static func boundedIdentity(_ name: String) -> String {
        var result = ""
        var bytes = 0
        for scalar in name.unicodeScalars {
            let width = scalar.utf8.count
            guard width <= 256 - bytes else { break }
            result.unicodeScalars.append(scalar)
            bytes += width
        }
        return result
    }
}

/// One work ledger covers BOTH scans, including discarded ordinary projections and the
/// failed candidate. Output nodes/bytes use a separate prospective, copy-on-admit ledger.
/// These are the existing limits, not new or enlarged allowances.
struct TypeAtlasDefaultReplyWork {
    private var budget = AttachedTypeReadBudget()
    private var refusedTextIsPrefix = false

    func reportingRefusal(_ error: ScriptingError) -> ScriptingError {
        let reported = budget.reportingRefusal(error)
        return refusedTextIsPrefix ? TypeAtlasDefaultReplyPolicy.labelPrefix(reported) : reported
    }

    mutating func visit() throws { try budget.charge(1) }

    mutating func row(_ entry: TypeAtlasEntry,
                      link: WorkspaceScriptingAPI.TypeAtlasSwiftObjCLink?,
                      checkpoint: () throws -> Void) throws {
        try checkpoint()
        try budget.charge(64)
        try text(entry.name); try text(entry.superclass)
        try WorkspaceScriptingAPI.visitImportedTypeText(in: entry) { try text($0) }
        try budget.charge(entry.members.count, times: 32)
        for member in entry.members {
            try checkpoint(); try text(member.name); try text(member.type)
        }
        try budget.charge(entry.users.count)
        try budget.charge(entry.conformances.count)
        for name in entry.conformances { try text(name) }
        try methods(entry.methods, checkpoint: checkpoint)
        for property in entry.declaredProperties ?? [] {
            try checkpoint(); try budget.charge(4)
            try text(property.name); try text(property.attributes)
        }
        for conformance in entry.swiftConformanceMethods ?? [] {
            try checkpoint(); try budget.charge(8); try text(conformance.protocolName)
            try methods(conformance.methods ?? [], checkpoint: checkpoint)
        }
        if let link {
            try budget.charge(32); try text(link.otherName)
            if case .name(let name) = link.otherID.key { try text(name) }
            for type in link.swiftFieldTypes ?? [] { try checkpoint(); try text(type) }
        }
    }

    private mutating func methods(_ values: [TypeAtlasMethod],
                                  checkpoint: () throws -> Void) throws {
        try budget.charge(values.count, times: 32)
        for method in values {
            try checkpoint(); try text(method.name); try text(method.category)
            try budget.charge(method.selectorUsers.count)
        }
    }

    private mutating func text(_ value: String?) throws {
        guard let value else { return }
        // Stop counting a pathological inline string at the finite work ceiling.
        let count = value.utf8.prefix(1_000_001).count
        do { try budget.charge(count) }
        catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
            // The inclusive prefix can equal the full string; never claim that it does.
            refusedTextIsPrefix = count == 1_000_001
            throw error
        }
    }
}
