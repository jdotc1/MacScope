import Foundation

/// Authority is the generation of the exact frozen snapshot, never its stored digest.
struct NativeDecompilerScriptingCaptureKey: Hashable, Sendable {
    let registryID: UUID
    let scriptingOwner: UUID
    let nativeImageValidationGenerationID: UUID
    let imageSlot: ImageSlot

    init(registryID: UUID, scriptingOwner: UUID,
         snapshot: WorkspaceSnapshot, imageSlot: ImageSlot) {
        self.registryID = registryID
        self.scriptingOwner = scriptingOwner
        nativeImageValidationGenerationID = snapshot.nativeImageValidationGenerationID
        self.imageSlot = imageSlot
    }

    static func rawRowCount(functions: Int, xrefs: Int, relocations: Int, symbols: Int) -> Int {
        var total = 0
        for count in [functions, xrefs, relocations, symbols] {
            guard count >= 0 else { return .max }
            let sum = total.addingReportingOverflow(count)
            guard !sum.overflow else { return .max }
            total = sum.partialValue
        }
        return total
    }

    static func permitsRetention(functions: Int, xrefs: Int, relocations: Int, symbols: Int) -> Bool {
        rawRowCount(functions: functions, xrefs: xrefs, relocations: relocations, symbols: symbols)
            <= 200_000
    }
}
