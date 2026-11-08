import Foundation

extension WorkspaceScriptingAPI {
    /// Optional display metadata for the exact name emitted by this reply.
    nonisolated static func scriptingDemangled(_ name: String) -> String? {
        guard name.hasPrefix("$s") || name.hasPrefix("$S") || name.hasPrefix("_$s")
                || name.hasPrefix("_$S") || name.hasPrefix("_TtC"),
              name.utf8.count <= SwiftDemangler.maxMangledLength,
              let rendered = Demangler.mangledToReadable(name),
              rendered != SwiftDemangler.tooComplexMarker, rendered != name else { return nil }
        return rendered
    }

    nonisolated static func demangleReply(_ arguments: ScriptValue) throws -> ScriptValue {
        guard let value = arguments["name"] else { throw ScriptingError.missingArgument("name") }
        guard let name = value.stringValue else { throw ScriptingError.invalidArgument("name must be a string") }
        guard name.utf8.count <= SwiftDemangler.maxMangledLength else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .outOfBounds,
                detail: "Field 'name' must contain at most 8192 UTF-8 bytes.", field: "name", maximum: 8_192))
        }
        guard name.hasPrefix("$s") || name.hasPrefix("$S") || name.hasPrefix("_$s")
                || name.hasPrefix("_$S") || name.hasPrefix("_TtC") else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .malformedInput,
                detail: "name is not a Swift mangled name", field: "name",
                expected: "a Swift mangled name ($s, $S, _$s, _$S or _TtC prefix)"))
        }
        let rendered = Demangler.mangledToReadable(name)
        if rendered == SwiftDemangler.tooComplexMarker {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "name exceeds the demangler's depth, work or output budget", field: "name"))
        }
        guard let rendered, rendered != name else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .malformedInput,
                detail: "the in-tree demangler does not cover this Swift name", field: "name"))
        }
        return .object(["name": .string(name), "demangled": .string(rendered), "language": .string("swift")])
    }
}
