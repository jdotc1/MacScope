import Foundation

/// The single `NSScriptCommand` subclass the shipped `MacScope.sdef` binds every command to.
/// It is a thin shell: identify the verb from the command description, bridge the evaluated
/// Apple-event arguments, run them against the front document's `WorkspaceScriptingAPI` via
/// `AppleScriptCommandRunner`, then map the result (or error) back to Cocoa scripting.
///
/// Everything it depends on is unit-tested without a running app (`AppleScriptArgumentBridge`,
/// `AppleScriptCommandRunner`, `AppleScriptCommandTranslator`, `ScriptingHost`); only this
/// dispatch — which needs a live Apple-event dispatcher — is verified by hand.
@objc(MacScopeScriptCommand)
final class MacScopeScriptCommand: NSScriptCommand {
    override func performDefaultImplementation() -> Any? {
        // Cocoa dispatches Apple events on the main thread, so the runner's main-actor
        // requirement is satisfied here. `ScriptValue` is Sendable, so it (and the Sendable
        // error fields) cross the assumeIsolated boundary cleanly; the Cocoa conversion and
        // error reporting happen outside the isolated block.
        // Read the Apple-event inputs and bridge them to Sendable `ScriptValue`s on this
        // (main) thread BEFORE the isolated block, so neither `self` nor the non-Sendable
        // `[String: Any]` arguments cross the isolation boundary.
        let verb = commandDescription.commandName
        let parameters = AppleScriptArgumentBridge.scriptValues(from: (evaluatedArguments as? [String: Any]) ?? [:])
        let isCurrentCommand = NSScriptCommand.current() === self

        var errorNumber = 0
        var errorMessage: String?
        let value: ScriptValue? = MainActor.assumeIsolated {
            guard let api = ScriptingHost.shared.activeAPI else {
                errorNumber = -1708 // errAEEventNotHandled
                errorMessage = "MacScope has no open document to script."
                return nil
            }
            do {
                let translated = try AppleScriptCommandTranslator.translate(command: verb, parameters: parameters)
                if translated.command == "compare-rebuild" {
                    // Cocoa only suspends its currently dispatched command. Schedule the
                    // MainActor continuation after this handler returns, as required by Cocoa.
                    guard isCurrentCommand,
                          let command = NSScriptCommand.current() as? MacScopeScriptCommand else {
                        throw ScriptingError.invalidArgument("compare-rebuild requires a live Apple event")
                    }
                    let snapshot = api.store.snapshot
                    let arguments = translated.arguments
                    command.suspendExecution()
                    Task { @MainActor [command] in
                        do {
                            let worker = Task.detached {
                                try RegenerationComparisonCommand.execute(arguments: arguments, snapshot: snapshot)
                            }
                            let result = try await withTaskCancellationHandler {
                                try await worker.value
                            } onCancel: {
                                worker.cancel()
                            }
                            let reply = try AppleScriptArgumentBridge.cocoaReply(from: result, command: verb)
                            command.resumeExecution(withResult: reply)
                        } catch {
                            command.scriptErrorNumber = -1750
                            command.scriptErrorString = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                            command.resumeExecution(withResult: nil)
                        }
                    }
                    return nil
                }
                return try AppleScriptCommandRunner.execute(translated, api: api)
            } catch {
                errorNumber = -1750 // errOSAGeneralError
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                return nil
            }
        }
        if let value {
            do {
                return try AppleScriptArgumentBridge.cocoaReply(from: value, command: verb)
            } catch {
                errorNumber = -1750
                errorMessage = "Unable to encode scripting reply: \(error.localizedDescription)"
            }
        }
        scriptErrorNumber = errorNumber
        scriptErrorString = errorMessage
        return nil
    }
}
