import Foundation

/// Runs one AppleScript verb against a `WorkspaceScriptingAPI`: bridges the Apple-event
/// arguments to `ScriptValue`, translates the verb to a safe scripting command via
/// `AppleScriptCommandTranslator` (which validates inputs and enforces the allowlist), then
/// executes it and returns the result. This is the entire live AppleScript path *minus* the
/// `NSScriptCommand` / Apple-event plumbing and the front-document lookup, so it is fully
/// unit-testable. The `NSScriptCommand` shell does nothing but resolve the front document's
/// API, read `evaluatedArguments`, and call this.
enum AppleScriptCommandRunner {
    /// Core: translate already-bridged `ScriptValue` parameters and execute. The Apple-event
    /// shell converts Cocoa arguments to Sendable `ScriptValue`s *before* entering its
    /// main-actor block, so this is the entry point it uses (nothing non-Sendable crosses
    /// the isolation boundary).
    @MainActor
    static func run(
        verb: String,
        parameters: [String: ScriptValue],
        api: WorkspaceScriptingAPI
    ) throws -> ScriptValue {
        let translated = try AppleScriptCommandTranslator.translate(command: verb, parameters: parameters)
        return try execute(translated, api: api)
    }

    /// Executes a translated command and discloses the analysis generation additively on
    /// object results (arrays and scalars keep their legacy shape). Shared with the live
    /// `NSScriptCommand` shell so there is one disclosure path.
    @MainActor
    static func execute(_ translated: TranslatedScriptCommand, api: WorkspaceScriptingAPI) throws -> ScriptValue {
        let capture = ScriptingGenerationCapture()
        let raw = try ScriptingGenerationCapture.$current.withValue(capture) {
            try api.execute(translated.command, arguments: translated.arguments)
        }
        // VI2c: the opt-in envelope uses the generation captured with the read, never a re-read.
        return translated.envelopesGeneration ? capture.enveloping(raw) : capture.disclosing(raw)
    }

    /// Convenience: bridge raw Cocoa scripting arguments, then run. Used by tests and any
    /// caller that already holds `[String: Any]` evaluated arguments.
    @MainActor
    static func run(
        verb: String,
        cocoaArguments: [String: Any],
        api: WorkspaceScriptingAPI
    ) throws -> ScriptValue {
        try run(verb: verb, parameters: AppleScriptArgumentBridge.scriptValues(from: cocoaArguments), api: api)
    }
}
