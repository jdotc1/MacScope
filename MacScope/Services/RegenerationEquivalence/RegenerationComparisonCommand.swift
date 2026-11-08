import Darwin
import Foundation

/// Compares already-captured images; an optional manifest is read only as caller declarations.
enum RegenerationComparisonCommand {
    static let command = ScriptingCommandInfo(name: "compare-rebuild",
        summary: "Compare two captured images using raw symbols; optionally bind declared states from manifestPath. Compilation, acceptance and external exclusions remain unassessed.",
        mutates: false, arguments: ["originalImage", "rebuiltImage", "outputDirectory", "manifestPath"])

    /// Called on a detached worker with a value snapshot captured before suspension.
    static func execute(arguments: ScriptValue, snapshot: WorkspaceSnapshot) throws -> ScriptValue {
        let budget = try RegenerationWorkBudget.start()
        guard case .object(let fields) = arguments,
              Set(["originalImage", "rebuiltImage", "outputDirectory"]).isSubset(of: Set(fields.keys)),
              Set(fields.keys).isSubset(of: Set(command.arguments)),
              let original = fields["originalImage"], original != .null,
              let rebuilt = fields["rebuiltImage"], rebuilt != .null,
              let outputPath = fields["outputDirectory"]?.stringValue,
              outputPath.hasPrefix("/"), !outputPath.contains("\0"),
              outputPath.utf8.count <= 4_096, !outputPath.split(separator: "/").contains("..") else {
            throw ScriptingError.invalidArgument("compare-rebuild requires two captured image selectors and a new absolute outputDirectory")
        }
        let destination = URL(fileURLWithPath: outputPath)
        let parent = destination.deletingLastPathComponent()
        let descriptor = try RegenerationFileSystem.openOrdinaryDirectory(parent)
        close(descriptor)
        try RegenerationToolRunner().checkStorage(at: parent)
        try budget.checkpoint()
        let originalSlot = try WorkspaceScriptingAPI.resolveImageSlot(.object(["image": original]), snapshot: snapshot)
        let rebuiltSlot = try WorkspaceScriptingAPI.resolveImageSlot(.object(["image": rebuilt]), snapshot: snapshot)
        var manifest: RegenerationManifest?
        var manifestBytes = 0
        if let manifestValue = fields["manifestPath"] {
            guard let path = manifestValue.stringValue, path.hasPrefix("/"), !path.contains("\0"),
                  path.utf8.count <= 4_096, !path.split(separator: "/").contains("..") else {
                throw ScriptingError.invalidArgument("manifestPath must be an absolute ordinary JSON file path")
            }
            let available = try RegenerationComparisonCoordinator.remainingInputBytes(snapshot: snapshot,
                originalSlot: originalSlot, rebuiltSlot: rebuiltSlot, includeManifestBindings: true, budget: budget)
            let bytes = try RegenerationCLICommands.readOrdinaryFile(URL(fileURLWithPath: path),
                budget: budget, maximumBytes: min(8_388_608, available))
            try budget.checkpoint()
            // Decoding is synchronous: byte-bounded before entry, checked again on return.
            manifest = try JSONDecoder().decode(RegenerationManifest.self, from: bytes)
            manifestBytes = bytes.count
            try budget.checkpoint()
        }
        let files = try RegenerationComparisonCoordinator.compareCaptured(snapshot: snapshot,
            originalSlot: originalSlot, rebuiltSlot: rebuiltSlot, manifest: manifest, dependencies: nil,
            manifestInputBytes: manifestBytes, budget: budget)
        try RegenerationFileSystem.publish(files: files, to: destination) { _ in try budget.checkpoint() }
        return .object(["ok": .bool(true),
            "json": .string(destination.appendingPathComponent("Equivalence/STRUCTURE-REPORT.json").path),
            "markdown": .string(destination.appendingPathComponent("Equivalence/STRUCTURE-REPORT.md").path),
            "limitations": .array([.string("Function pairing uses captured raw symbols and descriptive sizes only. Manifest states, when supplied, are declarations, not compilation or acceptance evidence. Body, control flow and external exclusions are unassessed.")])])
    }
}


extension WorkspaceScriptingAPI {
    nonisolated static var regenerationComparisonCommands: [DocumentCommand] {
        [(RegenerationComparisonCommand.command, { _, _ in
            // The synchronous registry must never perform parsing on MainActor.
            throw ScriptingError.invalidArgument("compare-rebuild requires the asynchronous live AppleScript path")
        })]
    }
}
