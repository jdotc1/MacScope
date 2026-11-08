import Foundation

// Resolver outcomes for the interactive pseudocode pane (OSR-1 PR B, slice 2b).
// The pane's render input is built from the snapshot alone; the qualified declaration batch
// lives in the store, so the store runs adapter + resolver and carries the outcomes in
// `PseudocodeRenderInput.objcMessageOutcomes`. Whole-binary export does not use this path.

/// Single entry per slot. A lookup with any differing key component is a miss, so a changed
/// snapshot (patch, reanalysis, override), function, or declaration generation never reuses it.
@MainActor
private final class ObjCMessageOutcomeCache {
    struct Key: Equatable {
        var slot: ImageSlot
        var functionStart: UInt64
        var snapshotRevision: UUID
        var declarationGeneration: UUID?
    }
    var entries: [ImageSlot: (key: Key, outcomes: [UInt64: ObjCMessageConstraintOutcome])] = [:]
}

@MainActor
private var objcMessageOutcomeCaches: [ObjectIdentifier: ObjCMessageOutcomeCache] = [:]

extension ObjCMessageConstraintOutcome {
    /// The annotation text the printer places after a dispatch call: the resolved owner, or the
    /// abstain reason. `not-objective-c-dispatch` says nothing.
    var pseudocodeNote: String? {
        switch self {
        case let .installed(constraint), let .macIROnly(constraint):
            let sign = constraint.methodSide == .class ? "+" : "-"
            return "\(sign)[\(constraint.receiverClassName) \(constraint.selector)]"
        case let .abstained(reason), let .contradiction(reason):
            return reason == .notObjectiveCDispatch ? nil : "objc: not resolved: \(reason.rawValue)"
        }
    }
}

extension WorkspaceStore {
    /// Cheap precheck on the render input's own rows, run before any MacIR build: only a
    /// `bl` whose target text or comment names `objc_msgSend` (including `objc_msgSend$sel`
    /// stubs) can be an Objective-C dispatch candidate.
    static func mayContainObjCDispatchCandidate(_ rows: [InstructionRow]) -> Bool {
        rows.contains { row in
            row.mnemonic.lowercased() == "bl"
                && (row.operands.contains("objc_msgSend") || (row.comment?.contains("objc_msgSend") ?? false))
        }
    }

    /// The render input with its resolver outcomes attached (the pane's single entry point).
    func withObjCMessageOutcomes(_ input: PseudocodeRenderInput) -> PseudocodeRenderInput {
        var result = input
        result.objcMessageNotes = objcMessageOutcomes(for: input).compactMapValues(\.pseudocodeNote)
        return result
    }

    /// Outcomes keyed by call address for the function in `input`; empty when the input has no
    /// dispatch candidate, no function, or no qualified evidence.
    func objcMessageOutcomes(for input: PseudocodeRenderInput) -> [UInt64: ObjCMessageConstraintOutcome] {
        guard let start = input.startAddress,
              Self.mayContainObjCDispatchCandidate(input.instructions) else { return [:] }
        let key = ObjCMessageOutcomeCache.Key(
            slot: input.imageSlot, functionStart: start,
            snapshotRevision: nativeDecompilerSnapshotRevision,
            declarationGeneration: objcDeclarationSourceGenerations[input.imageSlot])
        let cache: ObjCMessageOutcomeCache
        if let existing = objcMessageOutcomeCaches[ObjectIdentifier(self)] {
            cache = existing
        } else {
            cache = ObjCMessageOutcomeCache()
            objcMessageOutcomeCaches[ObjectIdentifier(self)] = cache
        }
        if let hit = cache.entries[input.imageSlot], hit.key == key { return hit.outcomes }

        // Same build arguments as `PseudocodePrinter.print(functionName:...)`.
        let function = PseudocodePrinter().buildFunction(
            functionName: input.functionName,
            startAddress: start,
            jumpTables: input.jumpTables,
            objcSelectors: input.objcSelectors,
            constantStrings: input.constantStrings,
            signatureOverrides: input.signatureOverrides,
            authoredCallSignaturesByTarget: input.authoredCallSignaturesByTarget,
            directCallVoidResultTargets: input.directCallVoidResultTargets,
            machineCallUsage: input.machineCallUsage,
            machineUsageContext: input.machineUsageContext,
            knownTailCallTargets: input.knownTailCallTargets,
            slotCallContracts: input.slotCallContracts,
            callerReturnWidth: input.callerReturnWidth,
            callerReturnType: input.callerReturnType,
            types: input.types,
            instructions: input.instructions
        )
        var outcomes: [UInt64: ObjCMessageConstraintOutcome] = [:]
        if let resolverInput = objcMessagePrototypeInput(for: function, in: input.imageSlot) {
            outcomes = ObjCMessagePrototypeResolver.resolve(resolverInput).outcomes
        }
        cache.entries[input.imageSlot] = (key, outcomes)
        return outcomes
    }
}
