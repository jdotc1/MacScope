import Foundation

/// Read-only: single-target resolution of a function's indirect calls through memory slots.
extension WorkspaceScriptingAPI {
    nonisolated static func indirectCallTargets(snapshot: WorkspaceSnapshot, function: FunctionSummary) -> ScriptValue {
        let slot = snapshot.primarySlot
        let functions = snapshot.analysis(in: slot)?.functions ?? []
        // Typed slots are image-wide (memoized per image); past the cap only function-local
        // resolution is sound.
        let wide = snapshot.imageWideIndirectCalls(in: slot, compute: true)
        let imageWide = wide != nil
        let report = wide ?? MacIRIndirectTargetResolution.resolve(
            functions: [PseudocodePrinter().buildFunction(
                functionName: snapshot.displayName(at: function.startAddress, in: slot, default: function.name),
                startAddress: function.startAddress,
                jumpTables: snapshot.resolvedJumpTables(in: slot),
                objcSelectors: snapshot.analysis(in: slot)?.objcSelectors ?? [:],
                constantStrings: snapshot.constantStrings(in: slot),
                signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
                authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
                types: snapshot.typeDefinitions,
                instructions: snapshot.pseudocodeTarget(selectedAddress: function.startAddress, in: slot)?.instructions ?? [])],
            functionStarts: Set(functions.map(\.startAddress)))
        return indirectCallTargetsValue(report, snapshot: snapshot, function: function, imageWide: imageWide)
    }

    /// Complete attached analysis is request-owned and invoked only on the snapshot worker.
    /// Input preparation, every function lift and resolution are separate cooperative phases.
    nonisolated static func boundedIndirectCallTargets(
        arguments: ScriptValue, snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        if let selector = indirectSelector(arguments),
           let function = snapshot.admittedIndirectSelector(selector, slot: snapshot.primarySlot),
           let indexed = snapshot.indexedIndirectReport(in: snapshot.primarySlot, start: function.startAddress) {
            try checkpoint()
            guard indexed.totalCount <= SnapshotAnalysisReadBudget.maximumLiftedRows else {
                throw SnapshotAnalysisReadBudget.refused
            }
            let value = indirectCallTargetsValue(indexed.report, snapshot: snapshot, function: function,
                                                 imageWide: true, indexed: indexed)
            try checkpoint()
            return functionReply(value, arguments: arguments, function: function)
        }
        var budget = SnapshotAnalysisReadBudget()
        try budget.prepareTypes(snapshot, checkpoint: checkpoint)
        guard try budget.prepareImage(snapshot, checkpoint: checkpoint) else {
            return try localIndirectCallTargets(arguments: arguments, snapshot: snapshot, checkpoint: checkpoint)
        }
        let function = try boundedSnapshotFunction(arguments, snapshot: snapshot, checkpoint: checkpoint)
        let slot = snapshot.primarySlot
        var failure: Error?
        let wide = snapshot.imageWideIndirectCalls(in: slot, compute: true, checkpoint: {
            guard failure == nil else { return false }
            do { try checkpoint(); return true } catch { failure = error; return false }
        }, admitInstructions: { rows in
            do { try budget.admitFunction(rows.count); return true } catch { failure = error; return false }
        })
        if let failure { throw failure }
        try checkpoint()
        let report: MacIRIndirectTargetResolution.Report
        if let wide {
            report = wide
        } else {
            let rows = snapshot.pseudocodeTarget(selectedAddress: function.startAddress, in: slot)?.instructions ?? []
            try budget.admitFunction(rows.count)
            try checkpoint()
            let built = PseudocodePrinter().buildFunction(
                functionName: snapshot.displayName(at: function.startAddress, in: slot, default: function.name),
                startAddress: function.startAddress, jumpTables: snapshot.resolvedJumpTables(in: slot),
                objcSelectors: snapshot.analysis(in: slot)?.objcSelectors ?? [:],
                constantStrings: snapshot.constantStrings(in: slot),
                signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
                authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
                types: snapshot.typeDefinitions, instructions: rows)
            try checkpoint()
            report = MacIRIndirectTargetResolution.resolve(functions: [built],
                functionStarts: Set(snapshot.functions.map(\.startAddress)))
        }
        try checkpoint()
        // Resolution has at most one result per indirect call in the admitted lifted rows.
        guard report.resolutions.count + report.refusals.count <= SnapshotAnalysisReadBudget.maximumLiftedRows else {
            throw SnapshotAnalysisReadBudget.refused
        }
        let value = indirectCallTargetsValue(report, snapshot: snapshot, function: function, imageWide: wide != nil)
        try checkpoint()
        if wide != nil, let selector = indirectSelector(arguments) {
            snapshot.admitIndirectSelector(selector, slot: slot, function: function)
        }
        return functionReply(value, arguments: arguments, function: function)
    }

    /// Function-local fallback after whole-image preparation refuses; never computes a cold memo.
    nonisolated private static func localIndirectCallTargets(
        arguments: ScriptValue, snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        let function = try boundedSnapshotFunction(arguments, snapshot: snapshot, checkpoint: checkpoint)
        let slot = snapshot.primarySlot
        guard (snapshot.analysis(in: slot)?.instructions.count ?? 0) <= SnapshotAnalysisReadBudget.maximumLocalImageRows else {
            throw SnapshotAnalysisReadBudget.refused
        }
        let wide = snapshot.imageWideIndirectCalls(in: slot, compute: false)
        let report: MacIRIndirectTargetResolution.Report
        if let wide {
            report = wide
        } else {
            var budget = SnapshotAnalysisReadBudget()
            let target = snapshot.pseudocodeTarget(selectedAddress: function.startAddress, in: slot)
            let rows = target?.instructions ?? []
            try budget.admitFunction(rows.count)
            try budget.take(rows.count)
            for (index, row) in rows.enumerated() {
                if index % 256 == 0 { try checkpoint() }
                try budget.text(row.bytes); try budget.text(row.mnemonic); try budget.text(row.operands)
            }
            try budget.take(snapshot.addressOverrides.count)
            try budget.prepareOverrides(snapshot, checkpoint: checkpoint)
            let body = target?.function ?? function
            for (index, entry) in (snapshot.analysis(in: slot)?.jumpTables ?? [:]).enumerated() {
                if index % 256 == 0 { try checkpoint() }
                let inside = body.endAddress > body.startAddress
                    ? entry.key >= body.startAddress && entry.key < body.endAddress
                    : entry.key == body.startAddress
                guard inside else { continue }
                try budget.take(1)
                try budget.take(entry.value.count)
            }
            try checkpoint()
            let built = PseudocodePrinter().buildFunction(
                functionName: snapshot.displayName(at: function.startAddress, in: slot, default: function.name),
                startAddress: function.startAddress, jumpTables: snapshot.resolvedJumpTables(in: slot),
                objcSelectors: snapshot.analysis(in: slot)?.objcSelectors ?? [:],
                constantStrings: snapshot.constantStrings(in: slot),
                signatureOverrides: snapshot.functionSignatureOverrides(in: slot),
                authoredCallSignaturesByTarget: snapshot.authoredCallSignaturesByTarget(in: slot),
                types: snapshot.typeDefinitions, instructions: rows)
            try checkpoint()
            report = MacIRIndirectTargetResolution.resolve(functions: [built],
                functionStarts: Set(snapshot.functions.map(\.startAddress)))
        }
        try checkpoint()
        guard report.resolutions.count + report.refusals.count <= SnapshotAnalysisReadBudget.maximumLiftedRows else {
            throw SnapshotAnalysisReadBudget.refused
        }
        let value = indirectCallTargetsValue(report, snapshot: snapshot, function: function, imageWide: wide != nil)
        try checkpoint()
        if wide != nil, let selector = indirectSelector(arguments) {
            snapshot.admitIndirectSelector(selector, slot: slot, function: function)
        }
        return functionReply(value, arguments: arguments, function: function)
    }

    nonisolated private static func indirectSelector(_ arguments: ScriptValue) -> IndirectSelectorMemo.Selector? {
        if let name = arguments["function"]?.stringValue { return .name(name) }
        return arguments["address"]?.addressValue.map { .address($0) }
    }

    nonisolated private static func indirectCallTargetsValue(
        _ report: MacIRIndirectTargetResolution.Report, snapshot: WorkspaceSnapshot,
        function: FunctionSummary, imageWide: Bool,
        indexed: IndirectCallResolutionMemo.FunctionReport? = nil
    ) -> ScriptValue {
        let slot = snapshot.primarySlot
        let selected = imageWide ? (indexed ?? snapshot.indexedIndirectReport(in: slot, start: function.startAddress)) : nil
        let selectedReport = selected?.report ?? report
        let functions = snapshot.analysis(in: slot)?.functions ?? []
        // A one-function report cannot establish type-wide uniqueness.
        let resolutions = selectedReport.resolutions.filter {
            if case .function = $0.scope { return true }
            return imageWide
        }
        let names = selected?.names ?? Dictionary(functions.map { ($0.startAddress, snapshot.displayName(at: $0.startAddress, in: slot, default: $0.name)) },
                               uniquingKeysWith: { first, _ in first })
        return .object([
            "address": .hex(function.startAddress),
            "imageWide": .bool(imageWide),
            "resolved": .array(resolutions.filter { $0.functionStart == function.startAddress }.map { resolution in
                let scope: String = switch resolution.scope {
                case .function: "function"
                case let .type(name): "type:\(name)"
                }
                return .object([
                    "call": .hex(resolution.callAddress), "target": .hex(resolution.target),
                    "targetName": names[resolution.target].map(ScriptValue.string) ?? .null,
                    "slot": .string(resolution.slot.description), "scope": .string(scope),
                ])
            }),
            "refused": .array(selectedReport.refusals.filter { $0.functionStart == function.startAddress }.map {
                .object(["call": .hex($0.callAddress), "reason": .string($0.reason.rawValue)])
            }),
        ])
    }
}

/// Explicit finite policy for cold attached analysis. Admission precedes index creation,
/// symbolization, signature projection and MacIR construction; no partial report is released.
struct SnapshotAnalysisReadBudget {
    static let maximumLiftedRows = 32_768
    static let maximumLocalImageRows = 16_777_216
    private var liftedRows = Self.maximumLiftedRows
    private var nodes = 65_536
    private var bytes = 1_048_576

    static var refused: ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "Snapshot analysis read exceeds the finite snapshot analysis budget.", narrowing: []))
    }

    mutating func take(_ count: Int) throws {
        guard count >= 0, count <= nodes else { throw Self.refused }
        nodes -= count
    }

    mutating func text(_ value: String?) throws {
        guard let value else { return }
        let count = value.utf8.prefix(4_097).count
        guard count <= 4_096, count <= bytes else { throw Self.refused }
        bytes -= count
    }

    mutating func admitFunction(_ count: Int) throws {
        guard count <= 2_048, count <= liftedRows else { throw Self.refused }
        liftedRows -= count
    }

    mutating func prepare(_ snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void) throws {
        try prepareTypes(snapshot, checkpoint: checkpoint)
        guard try prepareImage(snapshot, checkpoint: checkpoint) else { throw Self.refused }
    }

    mutating func prepareTypes(_ snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void) throws {
        try checkpoint()
        try WorkspaceScriptingAPI.validateSnapshotTypeDefinitions(snapshot.typeDefinitions, checkpoint: checkpoint)
    }

    /// Policy refusals choose the fallback; checkpoint errors always propagate.
    mutating func prepareImage(_ snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void) throws -> Bool {
        var checkpointFailure: Error?
        func checkedCheckpoint() throws {
            do { try checkpoint() }
            catch { checkpointFailure = error; throw error }
        }
        do {
            let slot = snapshot.primarySlot
            guard let analysis = snapshot.analysis(in: slot) else { return true }
            guard analysis.instructions.count <= Self.maximumLiftedRows else { throw Self.refused }
            try take(analysis.functions.count); try take(analysis.instructions.count)
            try take(analysis.symbols.count); try take(analysis.exports.count)
            try take(analysis.sections.count); try take(analysis.codeDataRanges.count)
            try take(analysis.objcSelectors.count); try take(analysis.constantStrings.count)
            try take(snapshot.addressOverrides.count); try take(analysis.jumpTables.count)
            let (exclusionWork, overflow) = analysis.codeDataRanges.count.multipliedReportingOverflow(by: analysis.instructions.count)
            guard !overflow, exclusionWork <= 1_048_576 else { throw Self.refused }
            for (index, row) in analysis.instructions.enumerated() {
                if index % 256 == 0 { try checkedCheckpoint() }
                try text(row.bytes); try text(row.mnemonic); try text(row.operands)
            }
            for function in analysis.functions { try checkedCheckpoint(); try text(function.name) }
            for symbol in analysis.symbols { try checkedCheckpoint(); try text(symbol.name) }
            for export in analysis.exports { try checkedCheckpoint(); try text(export.name) }
            for selector in analysis.objcSelectors.values { try checkedCheckpoint(); try text(selector) }
            for string in analysis.constantStrings.values { try checkedCheckpoint(); try text(string.text) }
            for targets in analysis.jumpTables.values { try checkedCheckpoint(); try take(targets.count) }
            try prepareOverrides(snapshot, checkpoint: checkedCheckpoint)
            try checkedCheckpoint()
            return true
        } catch {
            if let checkpointFailure { throw checkpointFailure }
            if let failure = error as? ScriptingError, failure == Self.refused { return false }
            throw error
        }
    }

    mutating func prepareOverrides(_ snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void) throws {
        for override in snapshot.addressOverrides.values {
            try checkpoint()
            try text(override.customName)
            if let names = override.registerNames {
                try take(names.count)
                for (key, name) in names { try checkpoint(); try text(key); try text(name) }
            }
            if let locals = override.stackLocals {
                try take(locals.count)
                for (key, local) in locals {
                    try checkpoint(); try text(key); try text(local.name); try text(local.typeName)
                }
            }
            if let hint = override.switchHint { try take(max(0, hint.entryCount)) }
            if let signature = override.signature {
                try text(signature.returnType)
                try take(signature.args.count)
                for arg in signature.args { try text(arg.name); try text(arg.type) }
            }
        }
    }
}
