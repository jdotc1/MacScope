import Foundation

extension WorkspaceScriptingAPI {
    /// True when a plain `±[Class selector]` request names a `±[Class(Category) selector]`
    /// raw or display name with the same side, class and complete selector. Callers apply
    /// it only to functions that did not already match the request exactly.
    nonisolated static func objcCategoryCandidates(
        _ requested: ObjCMethodNameParts?, rawName: String, displayName: String
    ) -> Bool {
        guard let requested, requested.category == nil else { return false }
        func matches(_ name: String) -> Bool {
            guard let candidate = ObjCMethodNameParts(name), candidate.category != nil else { return false }
            return candidate.isClassMethod == requested.isClassMethod
                && candidate.className == requested.className && candidate.selector == requested.selector
        }
        return matches(rawName) || matches(displayName)
    }

    /// Maps the exact and category-fallback matches, collected once in analysis order, to
    /// one function. More than one candidate with any fallback match is an Objective-C
    /// ambiguity listing every candidate; exact-only ambiguity and the zero-candidate
    /// refusal keep their existing errors and text.
    nonisolated static func resolveObjCCategoryCandidates(
        _ name: String, matches: [FunctionSummary], hasFallback: Bool,
        displayName: (FunctionSummary) -> String
    ) throws -> FunctionSummary {
        guard let first = matches.first else {
            throw ScriptingError.invalidArgument("no function named '\(name)'")
        }
        guard matches.count == 1 else {
            if hasFallback {
                throw ScriptingError.ambiguousObjCMethodSelector(name: name,
                    candidates: matches.map(displayName), addresses: matches.map(\.startAddress))
            }
            throw ScriptingError.ambiguousFunctionSelector(name: name, addresses: matches.map(\.startAddress))
        }
        return first
    }
}
