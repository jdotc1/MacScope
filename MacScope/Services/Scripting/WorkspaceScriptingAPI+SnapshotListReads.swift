import Foundation

/// Accounts for application-level name admission, not framework internals.
private struct ImportExportFilterBudget {
    let command: String
    private var visits = 0
    private var bytes = 0

    init(command: String) { self.command = command }

    private func refusal(_ detail: String, unit: MCPRefusalBudget.Unit, limit: Int, used: Int) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: "\(command) filter \(detail)",
            budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used), narrowing: []))
    }

    mutating func visit(_ checkpoint: () throws -> Void) throws {
        try checkpoint()
        guard visits < 100_000 else {
            throw refusal("requires another candidate visit", unit: .workSteps, limit: 100_000, used: visits)
        }
        visits += 1
    }

    mutating func admit(_ name: String, checkpoint: () throws -> Void) throws {
        try checkpoint()
        let view = name.utf8
        var index = view.startIndex
        var count = 0
        while index != view.endIndex {
            guard count < 4_096 else {
                throw refusal("name exceeds the per-name UTF-8 admission limit", unit: .bytes, limit: 4_096, used: count)
            }
            guard bytes < 1_048_576 else {
                throw refusal("requires another UTF-8 admission byte", unit: .bytes, limit: 1_048_576, used: bytes)
            }
            _ = view[index]
            view.formIndex(after: &index)
            count += 1
            bytes += 1
            if count.isMultiple(of: 256) { try checkpoint() }
        }
        try checkpoint()
    }
}

/// Bounds only application-level visits and UTF-8 admission, not Swift/Foundation internals.
private struct SectionFilterBudget {
    private var visits = 0
    private var bytes = 0
    private static let maxVisits = 100_000
    private static let maxNameBytes = 4_096
    private static let maxBytes = 1_048_576

    private func refusal(_ detail: String, unit: MCPRefusalBudget.Unit, limit: Int, used: Int) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: detail,
            budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used), narrowing: []))
    }

    mutating func visit(_ checkpoint: () throws -> Void) throws {
        try checkpoint()
        guard visits < Self.maxVisits else {
            throw refusal("sections filter requires another section/override visit",
                          unit: .workSteps, limit: Self.maxVisits, used: visits)
        }
        visits += 1
    }

    mutating func admit(_ name: String, checkpoint: () throws -> Void) throws {
        try checkpoint()
        let view = name.utf8
        var index = view.startIndex
        var count = 0
        while index != view.endIndex {
            guard count < Self.maxNameBytes else {
                throw refusal("sections filter name exceeds the per-name UTF-8 admission limit",
                              unit: .bytes, limit: Self.maxNameBytes, used: count)
            }
            guard bytes < Self.maxBytes else {
                throw refusal("sections filter requires another UTF-8 admission byte",
                              unit: .bytes, limit: Self.maxBytes, used: bytes)
            }
            _ = view[index]
            view.formIndex(after: &index)
            count += 1
            bytes += 1
            if count.isMultiple(of: 256) { try checkpoint() }
        }
        try checkpoint()
    }
}

private struct RelocationFilterBudget {
    private var visits = 0
    private var bytes = 0
    private static let maxVisits = 100_000
    private static let maxNameBytes = 4_096
    private static let maxBytes = 1_048_576

    private func refusal(_ detail: String, unit: MCPRefusalBudget.Unit, limit: Int, used: Int) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: detail,
            budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used), narrowing: []))
    }

    mutating func visit(_ checkpoint: () throws -> Void) throws {
        try checkpoint()
        guard visits < Self.maxVisits else {
            throw refusal("relocations filter requires another relocation visit",
                          unit: .workSteps, limit: Self.maxVisits, used: visits)
        }
        visits += 1
    }

    mutating func admit(_ name: String, checkpoint: () throws -> Void) throws {
        try checkpoint()
        let view = name.utf8
        var index = view.startIndex
        var count = 0
        while index != view.endIndex {
            guard count < Self.maxNameBytes else {
                throw refusal("relocations filter name exceeds the per-name UTF-8 admission limit",
                              unit: .bytes, limit: Self.maxNameBytes, used: count)
            }
            guard bytes < Self.maxBytes else {
                throw refusal("relocations filter requires another UTF-8 admission byte",
                              unit: .bytes, limit: Self.maxBytes, used: bytes)
            }
            _ = view[index]
            view.formIndex(after: &index)
            count += 1
            bytes += 1
            if count.isMultiple(of: 256) { try checkpoint() }
        }
        try checkpoint()
    }
}

/// Admission for the legacy flat lists and instruction selector, not a caller-supplied argument.
/// Only the attached executor opts into finite attached bounds; inline and ordinary async
/// callers keep their existing nil/no-limit and explicit-limit contracts.
enum SnapshotListReadScope: Equatable, Sendable {
    case nonattached
    case attached
}

struct ScriptingAnnotatedResult: Sendable {
    let result: ScriptValue
    var note: ScriptValue? = nil
}

/// One request owns this sink. No await or callback executes while its lock is held.
final class DispatchNoteSink: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: ScriptValue?
    func write(_ value: ScriptValue) {
        lock.lock(); defer { lock.unlock() }
        stored = value
    }
    func read() -> ScriptValue? {
        lock.lock(); defer { lock.unlock() }
        return stored
    }
}


/// The list reads that need only an immutable `WorkspaceSnapshot`. The command registry runs
/// them inline (CLI/AppleScript); async bindings and the attached executor run
/// the same code in a detached task over a snapshot captured on the MainActor, so building an
/// image-sized list never holds the UI (DP09-2 N3). `checkpoint` runs every
/// `checkpointInterval` rows and throws to cancel.
extension WorkspaceScriptingAPI {
    /// Async callers own the complete snapshot preparation and materialization task.
    func executeSnapshotListRead(_ command: String, arguments: ScriptValue) async throws -> ScriptValue {
        try await executeSnapshotListReadAnnotated(command, arguments: arguments, collectDispatchNote: false).result
    }

    func executeSnapshotListReadAnnotated(
        _ command: String, arguments: ScriptValue, collectDispatchNote: Bool = true
    ) async throws -> ScriptingAnnotatedResult {
        MCPFatalSignalReporter.prepareAlternateStack()
        try Task.checkCancellation()
        let snapshot = store.snapshot
        ScriptingGenerationCapture.current?.record(snapshot.analysisGenerationID)
        let graphContext = store.graphPageContext
        let journalHealth = command == "info" ? Self.editJournalHealthValue(store) : nil
        let catalog = command == "commands" ? Self.availableCommands : []
        let probe = snapshotReadCheckpoint
        let sink = collectDispatchNote && command == "callers" ? DispatchNoteSink() : nil
        let work = Task.detached(priority: Task.currentPriority) {
            try await Self.runSnapshotListWork(command, probe: probe) { checkpoint in
                try Self.snapshotListRead(command, arguments: arguments, snapshot: snapshot,
                    commandCatalog: catalog, checkpoint: checkpoint, dispatchNote: sink,
                    graphPageContext: graphContext)
            }
        }
        let output = try await withTaskCancellationHandler { try await work.value } onCancel: { work.cancel() }
        MCPFatalSignalReporter.prepareAlternateStack()
        try Task.checkCancellation()
        if Self.boundedCallCommands.contains(command) ||
            (Self.graphPageCommands.contains(command) && arguments["page"] == .bool(true)) {
            try graphContext.session.requireCurrent(graphContext)
        }
        return ScriptingAnnotatedResult(result: Self.withEditJournalHealth(output, health: journalHealth), note: sink?.read())
    }

    nonisolated static let snapshotListCommands: Set<String> = [
        "call-graph", "call-path",
        "functions", "instructions", "symbols", "strings", "imports", "exports", "sections", "relocations",
        "list-types", "list-image-types", "indirect-call-targets", "stack-locals", "recover-struct-candidate",
        "commands", "info", "xrefs", "implementations", "function-references", "endpoint-references", "function-facts", "callers", "callees", "name-at", "containing-function", "read-bytes", "resolve-symbol", "demangle",
        "bookmarks", "local-labels", "register-names", "manual-xrefs", "segment-overrides",
    ]
    nonisolated static let liftingSnapshotCommands: Set<String> = [
        "indirect-call-targets", "stack-locals", "recover-struct-candidate",
    ]

    /// Called inside the request-owned detached task, so mode resolution keeps
    /// that task's inputs. Non-lifting lists retain their direct worker path.
    nonisolated static func runSnapshotListWork(
        _ command: String,
        probe: (@Sendable () -> Void)?,
        body: @escaping @Sendable (@Sendable () throws -> Void) throws -> ScriptValue
    ) async throws -> ScriptValue {
        guard liftingSnapshotCommands.contains(command) else {
            return try body {
                probe?()
                try Task.checkCancellation()
            }
        }
        let cancellation = PseudocodeRenderingThread.Cancellation()
        return try await withTaskCancellationHandler {
            try await PseudocodeRenderingThread.runLifting {
                try body {
                    probe?()
                    try cancellation.check()
                    try Task.checkCancellation()
                }
            }
        } onCancel: {
            cancellation.cancel()
        }
    }

    nonisolated static let checkpointInterval = 256
    nonisolated static let maximumSnapshotSelectionWork = 100_000
    nonisolated static let maximumSnapshotRows = 5_000
    nonisolated static let maximumSnapshotInstructionRows = 2_000

    nonisolated static func snapshotListRead(
        _ command: String,
        arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        scope: SnapshotListReadScope = .nonattached,
        selectionWorkLimit: Int = maximumSnapshotSelectionWork,
        commandCatalog: [ScriptingCommandInfo] = [],
        checkpoint: () throws -> Void = {},
        dispatchNote: DispatchNoteSink? = nil,
        graphPageContext: GraphPageContext? = nil
    ) throws -> ScriptValue {
        if boundedCallCommands.contains(command) {
            return try boundedCallRead(command, arguments: arguments, snapshot: snapshot,
                                       context: graphPageContext, checkpoint: checkpoint)
        }
        if let page = try snapshotGraphPage(command, arguments: arguments, snapshot: snapshot,
                                             context: graphPageContext, checkpoint: checkpoint) { return page }
        if let page = try snapshotListPage(command, arguments: arguments, snapshot: snapshot, checkpoint: checkpoint) { return page }
        func flatRowLimit() throws -> Int? {
            let requested = try rowLimit(arguments)
            return scope == .attached ? min(requested ?? maximumSnapshotRows, maximumSnapshotRows) : requested
        }
        func rows<Element>(_ all: [Element], _ make: (Element) -> ScriptValue) throws -> ScriptValue {
            let limit = try flatRowLimit()
            let selected = all.prefix(limit ?? all.count)
            var out: [ScriptValue] = []
            out.reserveCapacity(selected.count)
            for (index, element) in selected.enumerated() {
                if index % checkpointInterval == 0 { try checkpoint() }
                out.append(make(element))
            }
            return .array(out)
        }

        switch command {
        case "endpoint-references":
            return try endpointReferences(arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "xrefs":
            return try snapshotXRefRead(arguments, snapshot: snapshot,
                selectionWorkLimit: selectionWorkLimit, checkpoint: checkpoint)

        case "functions":
            let filter = try ListRowFilter.parse(arguments, command: command)
            if !filter.isEmpty {
                try checkpoint()
                let limit = try flatRowLimit()
                guard limit != 0 else { return .array([]) }
                let selected = try FunctionFilterSelection.select(snapshot, matching: filter.matcher(), checkpoint: checkpoint)
                let result = try rows(selected) { entry in
                    .object(["name": .string(entry.displayName), "address": .hex(entry.function.startAddress),
                             "end": .hex(entry.function.endAddress), "confidence": .double(entry.function.confidence)])
                }
                try checkpoint()
                return result
            }
            return try rows(snapshot.functions) { function in
                .object(["name": .string(snapshot.displayName(at: function.startAddress, default: function.name)),
                         "address": .hex(function.startAddress), "end": .hex(function.endAddress),
                         "confidence": .double(function.confidence)])
            }

        case "list-types", "list-image-types":
            return try snapshotTypeListRead(command, arguments: arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "indirect-call-targets":
            return try boundedIndirectCallTargets(arguments: arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "stack-locals":
            return try boundedStackLocals(arguments: arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "recover-struct-candidate":
            return try boundedStructCandidate(arguments: arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "instructions":
            try checkpoint()
            let named = arguments["function"]?.stringValue != nil
            let function: FunctionSummary?
            let start: UInt64
            if named {
                function = try boundedSnapshotFunction(arguments, snapshot: snapshot, scope: scope, checkpoint: checkpoint)
                start = 0
            } else {
                function = nil
                start = try address(arguments, "address")
            }
            // Named-function reads historically ignore count and return the whole function.
            // Address reads keep their requested count (default 16). Only attach adds a cap.
            let requested: Int?
            if named {
                requested = nil
            } else if let value = arguments["count"], value != .null {
                let count: Int64?
                switch value {
                case .int(let value): count = value
                case .double(let value): count = Int64(exactly: value)
                default: count = nil
                }
                guard let count else {
                    throw ScriptingError.invalidArgument("count must be an exact integer in the Int64 range")
                }
                requested = Int(max(0, count))
            } else {
                requested = 16
            }
            let annotate: Bool
            switch arguments["annotate"] {
            case .none: annotate = false
            case .some(.bool(let value)): annotate = value
            case .some: throw ScriptingError.invalidArgument("annotate must be a boolean")
            }
            let count: Int? = scope == .attached
                ? min(requested ?? maximumSnapshotInstructionRows, maximumSnapshotInstructionRows)
                : requested
            guard count != 0 else { return .array([]) }
            var output: [ScriptValue] = []
            var selected: [InstructionRow] = []
            if annotate { selected.reserveCapacity(min(count ?? snapshot.instructions.count, snapshot.instructions.count)) }
            else { output.reserveCapacity(min(count ?? snapshot.instructions.count, snapshot.instructions.count)) }
            // Select incrementally, checkpointing nonmatches too. Never allocate an image-sized
            // filtered collection merely to take a small prefix (including named functions).
            for (index, row) in snapshot.instructions.enumerated() {
                guard scope != .attached || index < min(selectionWorkLimit, maximumSnapshotSelectionWork) else {
                    throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                        detail: "instruction selection exceeds the snapshot work budget",
                        budget: .init(unit: .workSteps, limit: Int64(min(selectionWorkLimit, maximumSnapshotSelectionWork))),
                        used: Int64(index + 1), narrowing: []))
                }
                if index % checkpointInterval == 0 { try checkpoint() }
                let matches: Bool
                if let function {
                    matches = function.endAddress > function.startAddress
                        ? row.address >= function.startAddress && row.address < function.endAddress
                        : row.address == function.startAddress
                } else {
                    matches = row.address >= start
                }
                guard matches else { continue }
                if annotate { selected.append(row) }
                else { output.append(instructionObject(row, snapshot)) }
                if let count, (annotate ? selected.count : output.count) == count { break }
            }
            try checkpoint()
            if annotate { return .array(try annotatedInstructionObjects(selected, snapshot: snapshot, checkpoint: checkpoint)) }
            return .array(output)

        case "symbols":
            let filter = try ListRowFilter.parse(arguments, command: command)
            var symbols = snapshot.symbols
            if !filter.isEmpty {
                let limit = try flatRowLimit()
                if limit == 0 { return .array([]) }
                let matches = try filter.matcher()
                let indices = try SymbolFilterSelection.indices(symbols, matching: matches, checkpoint: checkpoint)
                symbols = indices.map { symbols[$0] }
            }
            return try rows(symbols) { symbol in
                .object([
                    "name": .string(symbol.name),
                    "address": symbol.address.map(ScriptValue.hex) ?? .null,
                    "kind": .string(symbol.kind),
                ])
            }

        case "strings":
            let filter = try stringListFilter(arguments)
            if !filter.isEmpty {
                let limit = try flatRowLimit()
                if limit == 0 { return .array([]) }
                func retainedRows() throws -> ScriptValue {
                    let selected = try admittedStringOffsets(snapshot.stringLiterals, filter: filter,
                                                              limit: limit, checkpoint: checkpoint)
                    var out: [ScriptValue] = []
                    for index in selected {
                        try checkpoint()
                        let literal = snapshot.stringLiterals[index]
                        out.append(.object(["value": .string(literal.value), "address": .hex(literal.address)]))
                    }
                    try checkpoint()
                    return .array(out)
                }
                if snapshot.stringLiteralCoverage == .complete {
                    do { return try retainedRows() }
                    catch let error as ScriptingError {
                        guard case .structuredRefusal = error,
                              let source = try snapshotStringDiscovery(snapshot, checkpoint: checkpoint) else { throw error }
                        return try discoveryRows(source, filter: filter, limit: limit, checkpoint: checkpoint)
                    }
                }
                if let source = try snapshotStringDiscovery(snapshot, checkpoint: checkpoint) {
                    // A known unfinished scan must not look like a complete flat answer,
                    // even when the retained prefix already contains matching rows.
                    return try discoveryRows(source, filter: filter, limit: limit, checkpoint: checkpoint)
                }
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
                    detail: "strings source is unavailable and retained coverage is incomplete or unknown; use page:true to inspect retained rows and coverage",
                    narrowing: []))
            }
            return try rows(snapshot.stringLiterals) { literal in
                .object(["value": .string(literal.value), "address": .hex(literal.address)])
            }

        case "imports":
            if let nameContains = arguments["nameContains"] {
                let filter = try ListRowFilter.parse(.object(["nameContains": nameContains]), command: command)
                let limit = try flatRowLimit()
                guard limit != 0 else { return .array([]) }
                let matches = try filter.matcher()
                var budget = ImportExportFilterBudget(command: command)
                var result: [ScriptValue] = []
                var index = 0
                while index < snapshot.imports.count {
                    try budget.visit(checkpoint)
                    let item = snapshot.imports[index]
                    try budget.admit(item.name, checkpoint: checkpoint)
                    if matches(item.name, item.name, nil) {
                        result.append(.object(["name": .string(item.name),
                            "library": item.libraryName.map(ScriptValue.string) ?? .null,
                            "ordinal": item.libraryOrdinal.map { .int(Int64($0)) } ?? .null]))
                        if let limit, result.count == limit { break }
                    }
                    index += 1
                }
                try checkpoint()
                return .array(result)
            }
            return try rows(snapshot.imports) { item in
                .object([
                    "name": .string(item.name),
                    "library": item.libraryName.map(ScriptValue.string) ?? .null,
                    "ordinal": item.libraryOrdinal.map { .int(Int64($0)) } ?? .null,
                ])
            }

        case "exports":
            if let nameContains = arguments["nameContains"] {
                let filter = try ListRowFilter.parse(.object(["nameContains": nameContains]), command: command)
                let limit = try flatRowLimit()
                guard limit != 0 else { return .array([]) }
                let matches = try filter.matcher()
                var budget = ImportExportFilterBudget(command: command)
                var result: [ScriptValue] = []
                var index = 0
                while index < snapshot.exports.count {
                    try budget.visit(checkpoint)
                    let item = snapshot.exports[index]
                    try budget.admit(item.name, checkpoint: checkpoint)
                    if matches(item.name, item.name, nil) {
                        result.append(.object(["name": .string(item.name),
                            "address": item.address.map(ScriptValue.hex) ?? .null,
                            "source": .string(item.source)]))
                        if let limit, result.count == limit { break }
                    }
                    index += 1
                }
                try checkpoint()
                return .array(result)
            }
            return try rows(snapshot.exports) { item in
                .object([
                    "name": .string(item.name),
                    "address": item.address.map(ScriptValue.hex) ?? .null,
                    "source": .string(item.source),
                ])
            }

        case "sections":
            if let nameContains = arguments["nameContains"] {
                let filter = try ListRowFilter.parse(.object(["nameContains": nameContains]), command: command)
                let limit = try flatRowLimit()
                guard limit != 0 else { return .array([]) }
                let matches = try filter.matcher()
                var budget = SectionFilterBudget()
                var result: [ScriptValue] = []
                var sectionIndex = 0
                while sectionIndex < snapshot.sections.count {
                    try budget.visit(checkpoint)
                    let original = snapshot.sections[sectionIndex]
                    try budget.admit(original.name, checkpoint: checkpoint)
                    var display = original
                    var overrideIndex = 0
                    while overrideIndex < snapshot.segmentOverrides.count {
                        try budget.visit(checkpoint)
                        let candidate = snapshot.segmentOverrides[overrideIndex]
                        try budget.admit(candidate.originalName, checkpoint: checkpoint)
                        if candidate.originalName == original.name && candidate.imageSlot == snapshot.primarySlot {
                            if !candidate.isEmpty {
                                display.name = candidate.resolvedName(default: original.name)
                                display.address = candidate.rebased(original.address)
                            }
                            break
                        }
                        overrideIndex += 1
                    }
                    try budget.admit(display.name, checkpoint: checkpoint)
                    try checkpoint()
                    if matches(display.name, display.name, nil) {
                        result.append(.object([
                            "name": .string(display.name), "originalName": .string(original.name),
                            "address": .hex(display.address), "size": .count(display.size),
                            "fileOffset": .hex(display.fileOffset), "executable": .bool(display.isExecutable),
                            "zeroFill": .bool(display.isZeroFill),
                        ]))
                        if let limit, result.count == limit { break }
                    }
                    sectionIndex += 1
                }
                try checkpoint()
                return .array(result)
            }
            // Apply the same display override only to admitted rows, without mapping all sections.
            return try rows(snapshot.sections) { original in
                let override = snapshot.segmentOverride(for: original.name, in: snapshot.primarySlot)
                var display = original
                if let override {
                    display.name = override.resolvedName(default: original.name)
                    display.address = override.rebased(original.address)
                }
                return .object([
                    "name": .string(display.name),
                    "originalName": .string(original.name),
                    "address": .hex(display.address),
                    "size": .count(display.size),
                    "fileOffset": .hex(display.fileOffset),
                    "executable": .bool(display.isExecutable),
                    "zeroFill": .bool(display.isZeroFill),
                ])
            }

        case "relocations":
            func relocationRow(_ reloc: RelocationSummary) -> ScriptValue {
                var fields: [String: ScriptValue] = [
                    "address": .hex(reloc.address),
                    "section": .string(reloc.sectionName),
                    "typeCode": .count(UInt64(reloc.typeCode)),
                    "pcRelative": .bool(reloc.isPCRelative),
                ]
                if let typeName = reloc.typeName { fields["type"] = .string(typeName) }
                if let symbolName = reloc.symbolName { fields["symbol"] = .string(symbolName) }
                if let symbolIndex = reloc.symbolIndex { fields["symbolIndex"] = .count(UInt64(symbolIndex)) }
                if let addend = reloc.addend { fields["addend"] = .int(addend) }
                if reloc.widthInBytes > 0 { fields["width"] = .count(UInt64(reloc.widthInBytes)) }
                return .object(fields)
            }
            if let nameContains = arguments["nameContains"] {
                let filter = try ListRowFilter.parse(.object(["nameContains": nameContains]), command: command)
                let limit = try flatRowLimit()
                guard limit != 0 else { try checkpoint(); return .array([]) }
                let matches = try filter.matcher()
                var budget = RelocationFilterBudget()
                var result: [ScriptValue] = []
                for reloc in snapshot.relocations {
                    try budget.visit(checkpoint)
                    guard let symbol = reloc.symbolName else { continue }
                    try budget.admit(symbol, checkpoint: checkpoint)
                    try checkpoint()
                    if matches(symbol, symbol, nil) {
                        result.append(relocationRow(reloc))
                        if let limit, result.count == limit { break }
                    }
                }
                try checkpoint()
                return .array(result)
            }
            return try rows(snapshot.relocations, relocationRow)

        default:
            return try attachedSnapshotRead(command, arguments: arguments, snapshot: snapshot,
                commandCatalog: commandCatalog, checkpoint: checkpoint, dispatchNote: dispatchNote)
        }
    }

    /// Xref limits apply before selection and row encoding in both inline and detached reads.
    /// An absent limit retains direct rows within the finite result budget.
    /// Missing backing-storage authority is disclosed, never inferred from text.
    nonisolated static func snapshotXRefRead(
        _ arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        selectionWorkLimit: Int = maximumSnapshotSelectionWork,
        resultLimit: Int = maximumSnapshotRows,
        checkpoint: () throws -> Void = {}
    ) throws -> ScriptValue {
        let direction: WorkspaceSnapshot.XRefQueryDirection
        if let to = arguments["to"]?.addressValue {
            direction = .to(to)
        } else if let from = arguments["from"]?.addressValue {
            direction = .from(from)
        } else {
            throw ScriptingError.missingArgument("to or from")
        }
        let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
        let rowSlot = filter ?? snapshot.primarySlot
        let limit = try rowLimit(arguments)
        let rowCap = min(resultLimit, maximumSnapshotRows)
        let workCap = min(selectionWorkLimit, maximumSnapshotSelectionWork)
        var used = 0
        let charge: () throws -> Void = {
            used += 1
            if used > workCap { throw WorkspaceSnapshot.XRefQueryFailure.workBudget }
        }
        var refs: [XRef]
        var origins: [UInt64?] = []
        var objects: [UInt64] = []
        do {
            refs = try snapshot.boundedEffectiveXRefs(direction, in: filter, limit: limit,
                maximumRows: rowCap, maximumWork: workCap, chargeWork: charge, checkpoint: checkpoint)
            origins = Array(repeating: nil, count: refs.count)
            // Chained rows: references to a CFString object whose retained backing is the target.
            // `limit: 0` keeps its early exit in every table state.
            if case .to(let target) = direction, limit != 0,
               let table = snapshot.cfStringBackings(in: rowSlot) {
                objects = try cfStringObjects(backing: target, table: table, checkpoint: checkpoint)
                if !objects.isEmpty {
                    var suppressed = Set<XRefEndpointKey>()
                    for (index, edit) in snapshot.manualXRefs.enumerated() {
                        if index % checkpointInterval == 0 { try checkpoint() }
                        try charge()
                        if edit.imageSlot == rowSlot, edit.isSuppression, edit.to == target {
                            suppressed.insert(edit.endpointKey)
                        }
                    }
                    for object in objects {
                        let remaining = limit.map { $0 - refs.count }
                        if let remaining, remaining <= 0 { break }
                        let found = try snapshot.boundedEffectiveXRefs(.to(object), in: filter, limit: remaining,
                            maximumRows: rowCap - refs.count, maximumWork: workCap,
                            including: { !suppressed.contains(XRefEndpointKey(from: $0.from, to: target, kind: $0.kind)) },
                            chargeWork: charge, checkpoint: checkpoint)
                        for ref in found {
                            refs.append(XRef(id: ref.id, from: ref.from, to: target, kind: ref.kind))
                            origins.append(object)
                        }
                    }
                }
            }
        } catch WorkspaceSnapshot.XRefQueryFailure.workBudget {
            throw xrefWorkBudgetRefusal(limit: workCap)
        } catch WorkspaceSnapshot.XRefQueryFailure.resultBudget {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "xrefs exceeds the snapshot result budget; request a smaller limit",
                budget: .init(unit: .rows, limit: Int64(rowCap)),
                narrowing: ["limit", "imageSlot"]))
        }
        var rows = try namedGraphRows(refs, includeKind: true, snapshot: snapshot,
            slot: rowSlot, checkpoint: checkpoint)
        for (index, origin) in origins.enumerated() {
            guard let origin, case .object(var fields) = rows[index] else { continue }
            fields["via"] = .string("cfString")
            fields["cfString"] = .hex(origin)
            rows[index] = .object(fields)
        }
        var needsNotice = false
        if case .to(let target) = direction, limit != 0 {
            needsNotice = !objects.isEmpty
            if !needsNotice {
                needsNotice = try requiresCFStringStorageNotice(target: target,
                    constants: snapshot.constantStrings(in: rowSlot),
                    literals: snapshot.analysis(in: rowSlot)?.stringLiterals ?? [],
                    maximumWork: workCap, checkpoint: checkpoint)
            }
        }
        if needsNotice {
            // Empty flat arrays cannot carry a per-result disclosure. Preserve the
            // explicit zero-prefix exception, but never imply absent CFString edges.
            let table = snapshot.cfStringBackings(in: rowSlot)
            if rows.isEmpty {
                guard let table else { throw unavailableCFStringStorageRefusal() }
                guard table.complete else { throw partialCFStringStorageRefusal() }
                try checkpoint()
                return .array([])
            }
            let storage = cfStringStorage(table: table)
            for index in rows.indices {
                if index % checkpointInterval == 0 { try checkpoint() }
                if case .object(var fields) = rows[index] {
                    fields["cfStringStorage"] = storage
                    rows[index] = .object(fields)
                }
            }
        }
        try checkpoint()
        return .array(rows)
    }

    nonisolated static func xrefWorkBudgetRefusal(limit: Int) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "xrefs exceeds the snapshot work budget",
            budget: .init(unit: .workSteps, limit: Int64(limit)),
            narrowing: ["imageSlot"]))
    }

    /// Same name/address ambiguity policy as resolveFunction, with incremental checkpoints.
    /// Bounded analysis/metadata callers retain attached budgets by default. The legacy
    /// instruction-list route explicitly passes its scope so large nonattached lists remain valid.
    nonisolated static func boundedSnapshotFunction(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        scope: SnapshotListReadScope = .attached, checkpoint: () throws -> Void,
        candidateAdmission: ((FunctionSummary) throws -> Void)? = nil,
        matchAdmission: (() throws -> Void)? = nil
    ) throws -> FunctionSummary {
        let name = arguments["function"]?.stringValue
        let address = arguments["address"]?.addressValue
        guard name != nil || address != nil else { throw ScriptingError.missingArgument("function or address") }
        let requested = name.flatMap { ObjCMethodNameParts($0) }
        var hasFallback = false
        var matches: [FunctionSummary] = []
        var addressSelection = address.map { ScriptingFunctionAddressSelection(address: $0) }
        // A name that matches no function but is a strict `0x` + 1-16 hex digits string is
        // resolved exactly as `address` would be; any real name match wins over it.
        var hexNameSelection = address == nil ? name.flatMap(strictHexAddress).map {
            ScriptingFunctionAddressSelection(address: $0)
        } : nil
        for (index, function) in snapshot.functions.enumerated() {
            try candidateAdmission?(function)
            guard scope != .attached || index < maximumSnapshotSelectionWork else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "function selection exceeds the snapshot work budget",
                    budget: .init(unit: .workSteps, limit: Int64(maximumSnapshotSelectionWork)),
                    used: Int64(index + 1), narrowing: []))
            }
            if index % checkpointInterval == 0 { try checkpoint() }
            if let name {
                hexNameSelection?.consider(function)
                let display = snapshot.displayName(at: function.startAddress, default: function.name)
                let exact = function.name == name || display == name
                let fallback = !exact && objcCategoryCandidates(requested,
                    rawName: function.name, displayName: display)
                if exact || fallback {
                    guard scope != .attached || matches.count < maximumSnapshotRows else {
                        throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                            detail: "ambiguous function selection exceeds the result budget",
                            budget: .init(unit: .rows, limit: Int64(maximumSnapshotRows)),
                            used: Int64(matches.count + 1), narrowing: ["address"]))
                    }
                    try matchAdmission?()
                    matches.append(function)
                    hasFallback = hasFallback || fallback
                }
            } else {
                addressSelection?.consider(function)
            }
        }
        if let name {
            if matches.isEmpty, let hexNameSelection {
                return try hexNameSelection.resolved(snapshot: snapshot, slot: snapshot.primarySlot).function
            }
            return try resolveObjCCategoryCandidates(name, matches: matches, hasFallback: hasFallback) {
                snapshot.displayName(at: $0.startAddress, default: $0.name)
            }
        }
        guard let addressSelection else { throw ScriptingError.missingArgument("function or address") }
        return try addressSelection.resolved(snapshot: snapshot, slot: snapshot.primarySlot).function
    }

    /// Strict ASCII `0x` followed by 1-16 hex digits; no sign, whitespace or other forms.
    nonisolated static func strictHexAddress(_ text: String) -> UInt64? {
        let digits = text.utf8.dropFirst(2)
        guard text.utf8.starts(with: "0x".utf8), (1...16).contains(digits.count),
              digits.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) || ($0 >= 0x41 && $0 <= 0x46) })
        else { return nil }
        return UInt64(String(decoding: digits, as: UTF8.self), radix: 16)
    }
}
