import Foundation

/// Request-local descriptions layered on the graph namer's existing fields.
struct DataTargetDescriber {
    private let snapshot: WorkspaceSnapshot
    private let slot: ImageSlot
    private var literals: [UInt64: String] = [:]
    private var imports: [UInt64: String] = [:]
    private var constants: [UInt64: MacIRConstantString] = [:]
    private let includeStorageNotice: Bool
    private let backings: ImageConstantStringProvider.CFStringBackingTable?

    /// `includeCFStringStorage` adds the cfStringStorage disclosure to cfString rows. The
    /// instruction annotator passes false so its opt-in row format stays unchanged.
    nonisolated init(snapshot: WorkspaceSnapshot, slot: ImageSlot, targets: Set<UInt64>,
                     includeCFStringStorage: Bool = true, checkpoint: () throws -> Void,
                     admission: FunctionFactsAdmission? = nil) throws {
        self.includeStorageNotice = includeCFStringStorage
        self.snapshot = snapshot
        self.slot = slot
        self.backings = snapshot.cfStringBackings(in: slot)
        guard !targets.isEmpty else { return }
        let analysis = snapshot.analysis(in: slot)
        for (index, literal) in (analysis?.stringLiterals ?? []).enumerated() {
            try admission?.visit()
            if index % WorkspaceScriptingAPI.checkpointInterval == 0 { try checkpoint() }
            if targets.contains(literal.address) {
                try admission?.observeText(literal.value)
                literals[literal.address] = literal.value
            }
        }
        for (index, item) in (analysis?.indirectSymbols ?? []).enumerated() {
            try admission?.visit()
            if index % WorkspaceScriptingAPI.checkpointInterval == 0 { try checkpoint() }
            if targets.contains(item.address), imports[item.address] == nil,
               let name = item.symbolName, !name.isEmpty {
                try admission?.observeText(name, maximum: FunctionFactsAdmission.maximumNameBytes)
                imports[item.address] = name
            }
        }
        constants = snapshot.constantStrings(in: slot)
        // Admit only selected constant values, never all equal-text candidates. Equal text
        // never proves storage identity, so there is no equality scan.
        if let admission {
            try admission.visit(targets.count)
            for (index, target) in targets.enumerated() {
                if index % WorkspaceScriptingAPI.checkpointInterval == 0 { try checkpoint() }
                if let value = constants[target] { try admission.observeText(value.text) }
            }
        }
        try checkpoint()
    }

    nonisolated func describe(_ ref: XRef, named: Bool) -> [String: ScriptValue] {
        if let value = constants[ref.to], value.kind == .cfString {
            var fields: [String: ScriptValue] = ["targetKind": .string("cfString"), "value": .string(value.text)]
            if includeStorageNotice {
                if let table = backings {
                    if let backing = table.backings[ref.to] {
                        fields["cfStringStorage"] = .object(["status": .string("retained"), "backing": .hex(backing)])
                    } else if table.complete {
                        fields["cfStringStorage"] = WorkspaceScriptingAPI.unavailableCFStringStorage()
                    } else {
                        fields["cfStringStorage"] = WorkspaceScriptingAPI.partialCFStringStorage()
                    }
                } else {
                    fields["cfStringStorage"] = WorkspaceScriptingAPI.unavailableCFStringStorage()
                }
            }
            return fields
        }
        if let text = constants[ref.to].flatMap({ $0.kind == .cString ? $0.text : nil }) ?? literals[ref.to] {
            return ["targetKind": .string("cString"), "value": .string(text)]
        }
        if ref.kind == XRefKind.selref {
            return ["targetKind": .string("selector"),
                    "value": snapshot.analysis(in: slot)?.objcSelectors[ref.to].map(ScriptValue.string) ?? .null]
        }
        if ref.kind == XRefKind.classref {
            return ["targetKind": .string("class"),
                    "value": snapshot.analysis(in: slot)?.objcClassReferences[ref.to].flatMap { $0.name }.map(ScriptValue.string) ?? .null]
        }
        if let name = imports[ref.to] {
            return ["targetKind": .string("import"),
                    "value": .string(snapshot.displayName(at: ref.to, in: slot, default: name))]
        }
        return ["targetKind": .string(named ? "symbol" : "data")]
    }
}

extension WorkspaceScriptingAPI {
    nonisolated static func unavailableCFStringStorage() -> ScriptValue {
        .object(["status": .string("unavailable"),
                 "reason": .string("backingAddressNotRetained")])
    }

    nonisolated static func partialCFStringStorage() -> ScriptValue {
        .object(["status": .string("partial"), "reason": .string("cfStringWalkIncomplete")])
    }

    nonisolated static func retainedCFStringStorage() -> ScriptValue {
        .object(["status": .string("retained")])
    }

    /// Row and page disclosure for a read of a retained, partial or absent backing table.
    nonisolated static func cfStringStorage(table: ImageConstantStringProvider.CFStringBackingTable?) -> ScriptValue {
        guard let table else { return unavailableCFStringStorage() }
        return table.complete ? retainedCFStringStorage() : partialCFStringStorage()
    }

    nonisolated static func partialCFStringStorageRefusal() -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
            detail: "xrefs found no references to this address; CFString backing storage was only partly retained because the CFString walk was capped or could not resolve every data pointer",
            narrowing: []))
    }

    /// objects(T): every CFString object whose retained backing is `target`, ascending. The
    /// scan is bounded by the validated table size and is not charged to any work budget.
    nonisolated static func cfStringObjects(
        backing target: UInt64, table: ImageConstantStringProvider.CFStringBackingTable,
        checkpoint: () throws -> Void
    ) throws -> [UInt64] {
        var objects: [UInt64] = []
        for (index, entry) in table.backings.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            if entry.value == target { objects.append(entry.key) }
        }
        objects.sort()
        try checkpoint()
        return objects
    }

    nonisolated static func unavailableCFStringStorageRefusal() -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
            detail: "xrefs found no direct references to this address; references through CFString backing storage are unavailable because backing addresses were not retained",
            narrowing: []))
    }

    /// Classify by retained address/kind only. An object map entry wins over a
    /// colliding literal; metadata and legacy literals need not be in the map.
    /// Exhausted address-only work conservatively discloses uncertainty, never
    /// claims absence. This independent preparation cap does not rescan xrefs.
    nonisolated static func requiresCFStringStorageNotice(
        target: UInt64, constants: [UInt64: MacIRConstantString],
        literals: [StringLiteralSummary], maximumWork: Int,
        checkpoint: () throws -> Void
    ) throws -> Bool {
        try checkpoint()
        if let constant = constants[target] { return constant.kind == .cString }
        let bound = min(max(0, maximumWork), maximumSnapshotSelectionWork)
        for (index, literal) in literals.enumerated() {
            if index >= bound { try checkpoint(); return true }
            if index % checkpointInterval == 0 { try checkpoint() }
            if literal.address == target { try checkpoint(); return true }
        }
        try checkpoint()
        return false
    }

    nonisolated static func functionIdentityFields(
        _ function: FunctionSummary, view: WorkspaceSnapshot, slot: ImageSlot,
        snapshot: WorkspaceSnapshot
    ) -> [String: ScriptValue] {
        let name = view.displayName(at: function.startAddress, in: slot, default: function.name)
        var fields = imageProvenanceFields(slot: slot, snapshot: snapshot)
        fields["name"] = .string(name)
        fields["start"] = .hex(function.startAddress)
        fields["end"] = .hex(function.endAddress)
        if let demangled = scriptingDemangled(name) { fields["demangled"] = .string(demangled) }
        return fields
    }
}
