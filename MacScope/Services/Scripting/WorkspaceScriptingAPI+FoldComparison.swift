import Foundation

extension WorkspaceScriptingAPI {
    /// FD-COMPARISON: for a non-empty fold request, renders the same frozen snapshot once more
    /// with `fold: nil` and reports both complete-document line counts (before paging).
    /// Same printer, MacIR function, snapshot and checkpoint as the folded render.
    nonisolated static func applyFoldComparisonFields(
        _ fields: inout [String: ScriptValue],
        printer: PseudocodePrinter,
        irFunction: MacIRFunction,
        snapshot: WorkspaceSnapshot,
        slot: ImageSlot,
        function: FunctionSummary,
        resolution: PseudocodeTargetResolution?,
        target: (function: FunctionSummary, instructions: [InstructionRow])?,
        foldedLineCount: Int,
        checkpoint: () throws -> Void
    ) throws {
        let baselineDocument = try printer.print(
            function: irFunction,
            ownDirectCallAddresses: snapshot.ownDirectCallAddresses(in: slot),
            types: snapshot.typeDefinitions,
            nameOverrides: snapshot.functionNameOverrides(in: slot),
            registerNameOverrides: snapshot.registerNameOverrides(forProcedureAt: function.startAddress, in: slot),
            stackLocalOverrides: snapshot.stackLocalOverrides(forProcedureAt: function.startAddress, in: slot),
            fold: nil,
            userComments: PseudocodeUserComments(
                textByAddress: resolution?.userComments ?? [:],
                bodyAddresses: Set((target?.instructions ?? []).map(\.address)),
                excludedAddresses: snapshot.codeExcludedAddresses(in: slot)),
            checkpoint: checkpoint
        )
        fields["unfoldedLineCount"] = .int(Int64(baselineDocument.lines.count))
        fields["foldedLineCount"] = .int(Int64(foldedLineCount))
    }
}
