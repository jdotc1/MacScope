import Foundation

extension WorkspaceScriptingAPI {
    /// The remaining attached reads share the request-owned snapshot worker. Preserve legacy
    /// replies inside the budget; refuse excessive work explicitly instead of returning a
    /// truncated result that looks complete. Nothing here touches the live store.
    nonisolated static func attachedSnapshotRead(
        _ command: String,
        arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        commandCatalog: [ScriptingCommandInfo] = [],
        checkpoint: () throws -> Void,
        dispatchNote: DispatchNoteSink? = nil
    ) throws -> ScriptValue {
        try checkpoint()
        var work = 0
        func step() throws {
            guard work < maximumSnapshotSelectionWork else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "\(command) exceeds the snapshot work budget",
                    budget: .init(unit: .workSteps, limit: Int64(maximumSnapshotSelectionWork)),
                    used: Int64(work + 1), narrowing: []))
            }
            if work % checkpointInterval == 0 { try checkpoint() }
            work += 1
        }
        func append(_ row: ScriptValue, to rows: inout [ScriptValue]) throws {
            guard rows.count < maximumSnapshotRows else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "\(command) exceeds the snapshot result budget",
                    budget: .init(unit: .rows, limit: Int64(maximumSnapshotRows)),
                    used: Int64(rows.count + 1), narrowing: []))
            }
            rows.append(row)
        }
        func checkRows(_ count: Int) throws {
            guard count <= maximumSnapshotRows else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "\(command) exceeds the snapshot result budget",
                    budget: .init(unit: .rows, limit: Int64(maximumSnapshotRows)),
                    used: Int64(count), narrowing: []))
            }
        }
        switch command {
        case "function-facts":
            return try functionFacts(arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "commands":
            var rows: [ScriptValue] = []
            for info in commandCatalog {
                try step()
                try append(.object([
                    "name": .string(info.name), "summary": .string(info.summary),
                    "mutates": .bool(info.mutates),
                    "arguments": .array(info.arguments.map(ScriptValue.string)),
                ]), to: &rows)
            }
            return .array(rows)

        case "info":
            let binary = snapshot.binaries.first
            return .object([
                "name": .string(binary?.name ?? ""),
                "format": .string(binary?.kind ?? ""),
                "architecture": .string(binary?.architecture ?? ""),
                "slice": selectedSliceValue(binary),
                "functionCount": .int(Int64(snapshot.functions.count)),
                "instructionCount": .int(Int64(snapshot.instructions.count)),
                "symbolCount": .int(Int64(snapshot.symbols.count)),
                "stringLiteralCoverage": snapshot.stringLiteralCoverage.map { coverage in
                    .object(["status": .string(coverage.status),
                             "stopReason": coverage.stopReason.map { .string($0.rawValue) } ?? .null])
                } ?? .null,
            ].merging(try stringCountFields(snapshot, checkpoint: checkpoint)) { _, count in count })

        case "containing-function":
            let target = try address(arguments, "address")
            let slot = try resolveImageSlot(arguments, snapshot: snapshot)
            let view = imageProjection(of: snapshot, in: slot)
            let function = try boundedSnapshotFunction(.object(["address": .hex(target)]),
                snapshot: view, checkpoint: checkpoint)
            let fields = functionIdentityFields(function, view: view, slot: slot, snapshot: snapshot)
            return functionReply(.object(fields), arguments: .object(["address": .hex(target)]), function: function)

        case "name-at":
            let target = try address(arguments, "address")
            var parsed: String?
            for function in snapshot.functions {
                try step()
                if function.startAddress == target { parsed = function.name; break }
            }
            if parsed == nil {
                for symbol in snapshot.symbols {
                    try step()
                    if symbol.address == target { parsed = symbol.name; break }
                }
            }
            let name = snapshot.displayName(at: target, default: parsed ?? "")
            if let demangled = scriptingDemangled(name) {
                return .object(["name": .string(name), "demangled": .string(demangled)])
            }
            return name.isEmpty ? .null : .string(name)

        case "resolve-symbol":
            guard let value = arguments["name"] else { throw ScriptingError.missingArgument("name") }
            guard let name = value.stringValue else { throw ScriptingError.invalidArgument("name must be a string") }
            let query = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !query.isEmpty, let analysis = snapshot.analysis(in: snapshot.primarySlot) else { return .null }
            func matches(_ candidate: String) -> Bool {
                if candidate.caseInsensitiveCompare(query) == .orderedSame { return true }
                let candidate = candidate.hasPrefix("_") ? String(candidate.dropFirst()) : candidate
                let query = query.hasPrefix("_") ? String(query.dropFirst()) : query
                return !query.isEmpty && candidate.caseInsensitiveCompare(query) == .orderedSame
            }
            for function in analysis.functions {
                try step()
                let authored = snapshot.addressOverrides[
                    ImageAddress(slot: snapshot.primarySlot, address: function.startAddress)
                ]?.customName
                if matches(authored ?? function.name) || matches(function.name) { return .hex(function.startAddress) }
            }
            for item in analysis.exports {
                try step()
                if matches(item.name) { return item.address.map(ScriptValue.hex) ?? .null }
            }
            for item in analysis.symbols {
                try step()
                if let address = item.address, matches(item.name) { return .hex(address) }
            }
            return .null

        case "callers", "callees":
            if command == "callers", try selectorArgument(arguments) != nil || selectorsArgument(arguments) != nil {
                return try selectorSendSiteRows(arguments, snapshot: snapshot, checkpoint: checkpoint)
            }
            // `imageSlot` filters the graph to one image; unfiltered reads keep the primary image.
            // Either way each row names the image that produced it.
            let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
            let view = filter.map { imageProjection(of: snapshot, in: $0) } ?? snapshot
            let function: FunctionSummary
            do {
                function = try boundedSnapshotFunction(arguments, snapshot: view, checkpoint: checkpoint)
            } catch let error as ScriptingError {
                if case .ambiguousObjCMethodSelector = error { throw error }
                if command == "callers",
                   let rows = try stubCallerRows(arguments: arguments, snapshot: snapshot, view: view,
                       filter: filter, scope: .attached, checkpoint: checkpoint) { return rows }
                throw error
            }
            if command == "callers" {
                try requireCallersContainment(arguments, function: function)
            }
            let rowSlot = filter ?? view.primarySlot
            var rows: [ScriptValue] = []
            var edges: [XRef] = []
            try visitFunctionCallEdges(reverse: command == "callers", function: function, view: view,
                command: command, workUsed: work, checkpoint: checkpoint, step: step) { ref in
                try append(callEdgeRow(ref, slot: rowSlot), to: &rows)
                edges.append(ref)
            }
            rows = try namedGraphRows(edges, includeKind: false, snapshot: view,
                slot: rowSlot, checkpoint: checkpoint)
            func selector(_ name: String) -> String? {
                guard name.hasPrefix("-[") || name.hasPrefix("+["), name.hasSuffix("]") else { return nil }
                let content = name.dropFirst(2).dropLast()
                guard let space = content.firstIndex(of: " "), space != content.startIndex else { return nil }
                let tail = content[content.index(after: space)...]
                guard !tail.isEmpty, !tail.contains(where: { $0.isWhitespace }) else { return nil }
                return String(tail)
            }
            if command == "callers", rows.isEmpty, let dispatchNote, let selector = selector(function.name) {
                var stubAddress: UInt64?
                let stubName = "_objc_msgSend$" + selector
                do {
                    for candidate in view.functions {
                        try step()
                        if candidate.name == stubName,
                           stubAddress.map({ candidate.startAddress < $0 }) ?? true {
                            stubAddress = candidate.startAddress
                        }
                    }
                    for symbol in view.symbols {
                        try step()
                        if symbol.name == stubName, let address = symbol.address,
                           stubAddress.map({ address < $0 }) ?? true {
                            stubAddress = address
                        }
                    }
                } catch let error as ScriptingError {
                    guard work == maximumSnapshotSelectionWork,
                          case .structuredRefusal(let refusal) = error,
                          refusal.code == .budgetExceeded,
                          refusal.budget?.unit == .workSteps else { throw error }
                    stubAddress = nil
                }
                var retryArguments: [String: ScriptValue] = ["selector": .string(selector)]
                if let filter { retryArguments["imageSlot"] = .int(Int64(filter.rawValue)) }
                var note: [String: ScriptValue] = [
                    "code": .string("dynamicDispatch"), "selector": .string(selector),
                    "text": .string("No direct callers of \(String(function.name.prefix(1_024))) were found, but it is an Objective-C method and may be reached by dynamic dispatch through objc_msgSend (selector \(selector)). Try callers with selector \(selector) to list its send sites."),
                    "try": .object(["tool": .string("callers"), "arguments": .object(retryArguments)]),
                ]
                if let stubAddress { note["stubAddress"] = .hex(stubAddress) }
                dispatchNote.write(.object(note))
            }
            return .array(rows)

        case "xrefs":
            return try snapshotXRefRead(arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "implementations":
            return try selectorImplementationRows(arguments, snapshot: snapshot, checkpoint: checkpoint)

        case "function-references":
            let limit = try rowLimit(arguments)
            if let limit, limit > maximumSnapshotRows { try checkRows(limit) }
            let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
            let view = filter.map { imageProjection(of: snapshot, in: $0) } ?? snapshot
            let function = try boundedSnapshotFunction(arguments, snapshot: view, checkpoint: checkpoint)
            // A one-byte half-open range cannot represent the final UInt64 address.
            let finalAddressOnly = function.startAddress == UInt64.max && function.endAddress <= function.startAddress
            let range = finalAddressOnly ? nil : view.functionRange(function)
            let lower = range?.lowerBound ?? UInt64.max
            let upperInclusive = range.map { $0.upperBound - 1 } ?? UInt64.max
            let rowSlot = filter ?? view.primarySlot
            var refs: [XRef] = []
            var seen = Set<XRefEndpointKey>()
            if limit != 0 {
                var suppressed = Set<XRefEndpointKey>()
                for edit in view.manualXRefs {
                    try step()
                    if edit.imageSlot == rowSlot && edit.isSuppression &&
                        edit.from >= lower && edit.from <= upperInclusive {
                        suppressed.insert(edit.endpointKey)
                    }
                }
                func admit(_ ref: XRef) throws -> Bool {
                    guard ref.from >= lower, ref.from <= upperInclusive, ref.kind != XRefKind.call else { return true }
                    let key = XRefEndpointKey(from: ref.from, to: ref.to, kind: ref.kind)
                    guard !suppressed.contains(key), seen.insert(key).inserted else { return true }
                    try checkRows(refs.count + 1)
                    refs.append(ref)
                    return refs.count != limit
                }
                do {
                    try view.visitXRefCandidates(.from, lower: lower, upperInclusive: upperInclusive,
                        in: rowSlot, maximumCandidates: maximumSnapshotSelectionWork - work,
                        checkpoint: checkpoint) { ref in
                        try step()
                        return try admit(ref)
                    }
                } catch XRefEndpointIndex.SelectionFailure.workBudget {
                    for ref in view.analysis(in: rowSlot)?.xrefs ?? [] {
                        try step()
                        if try !admit(ref) { break }
                    }
                }
                if refs.count != limit {
                    for edit in view.manualXRefs {
                        try step()
                        guard edit.imageSlot == rowSlot, !edit.isSuppression else { continue }
                        if try !admit(XRef(id: edit.id, from: edit.from, to: edit.to, kind: edit.kind)) { break }
                    }
                }
            }
            let named = try namedGraphRows(refs, includeKind: true, snapshot: view,
                slot: rowSlot, checkpoint: checkpoint)
            let describer = try DataTargetDescriber(snapshot: view, slot: rowSlot,
                targets: Set(refs.map(\.to)), checkpoint: checkpoint)
            var rows: [ScriptValue] = []
            for (index, ref) in refs.enumerated() {
                if index % checkpointInterval == 0 { try checkpoint() }
                if case .object(var row) = named[index] {
                    row.merge(describer.describe(ref, named: row["toName"]?.stringValue != nil)) { old, _ in old }
                    rows.append(.object(row))
                }
            }
            var fields = functionIdentityFields(function, view: view, slot: rowSlot, snapshot: snapshot)
            fields["stringLiteralCoverage"] = view.stringLiteralCoverage.map { coverage in
                .object(["status": .string(coverage.status),
                         "stopReason": coverage.stopReason.map { .string($0.rawValue) } ?? .null])
            } ?? .null
            // Literal completeness never establishes CFString backing-storage identity; only a
            // retained backing table discloses retained or partial storage.
            fields["cfStringStorage"] = cfStringStorage(table: view.cfStringBackings(in: rowSlot))
            fields["references"] = .array(rows)
            return functionReply(.object(fields), arguments: arguments, function: function)

        case "register-names":
            let function = try boundedSnapshotFunction(arguments, snapshot: snapshot, checkpoint: checkpoint)
            let raw = snapshot.addressOverrides[
                ImageAddress(slot: snapshot.primarySlot, address: function.startAddress)
            ]?.registerNames ?? [:]
            try checkRows(raw.count)
            let names = snapshot.registerNameOverrides(forProcedureAt: function.startAddress)
            var renames: [String: ScriptValue] = [:]
            for (register, name) in names { try step(); renames[register] = .string(name) }
            return functionReply(.object(["address": .hex(function.startAddress), "renames": .object(renames)]), arguments: arguments, function: function)

        case "local-labels":
            var labels: [(UInt64, String)] = []
            for (key, override) in snapshot.addressOverrides {
                try step()
                guard key.slot == snapshot.primarySlot,
                      let label = override.localLabel, !label.isEmpty else { continue }
                try checkRows(labels.count + 1)
                labels.append((key.address, label))
            }
            labels.sort { $0.0 < $1.0 }
            var rows: [ScriptValue] = []
            for (address, label) in labels {
                try step()
                try append(.object(["address": .hex(address), "label": .string(label)]), to: &rows)
            }
            return .array(rows)

        case "manual-xrefs":
            var rows: [ScriptValue] = []
            for edit in snapshot.manualXRefs {
                try step()
                guard edit.imageSlot == snapshot.primarySlot else { continue }
                try append(.object([
                    "from": .hex(edit.from), "to": .hex(edit.to), "kind": .string(edit.kind),
                    "suppressed": .bool(edit.isSuppression),
                ]), to: &rows)
            }
            return .array(rows)

        case "bookmarks":
            var bookmarks: [Bookmark] = []
            for bookmark in snapshot.bookmarks {
                try step()
                guard bookmark.imageSlot == snapshot.primarySlot else { continue }
                try checkRows(bookmarks.count + 1)
                bookmarks.append(bookmark)
            }
            bookmarks.sort { $0.address == $1.address ? $0.name < $1.name : $0.address < $1.address }
            var rows: [ScriptValue] = []
            for bookmark in bookmarks {
                try step()
                try append(.object(["address": .hex(bookmark.address), "name": .string(bookmark.name)]), to: &rows)
            }
            return .array(rows)

        case "segment-overrides":
            try checkRows(snapshot.segmentOverrides.count)
            let overrides = snapshot.segmentOverrides.sorted { $0.originalName < $1.originalName }
            var rows: [ScriptValue] = []
            for override in overrides {
                try step()
                try append(.object([
                    "section": .string(override.originalName),
                    "displayName": override.displayName.map(ScriptValue.string) ?? .null,
                    "rebaseDelta": .int(override.rebaseDelta),
                ]), to: &rows)
            }
            return .array(rows)

        case "read-bytes":
            let target = try address(arguments, "address")
            let requested = try readBytesCount(arguments)
            let slot = try resolveImageSlot(arguments, snapshot: snapshot)
            let analysis = snapshot.analysis(in: slot)
            var selected: SectionSummary?
            for section in analysis?.sections ?? [] {
                try step()
                if section.address <= target && target < section.address &+ section.size { selected = section; break }
            }
            guard let section = selected else {
                throw ScriptingError.invalidArgument("address \(ScriptValue.hex(target).stringValue ?? "") is not in any mapped section")
            }
            let delta = target - section.address
            let available = min(UInt64(requested), section.size - delta)
            let bytes = analysis?.imageBytes ?? Data()
            let (sliceStart, overflowed) = section.fileOffset.addingReportingOverflow(delta)
            let length: Int
            if section.isZeroFill { length = Int(min(available, UInt64(Int.max))) }
            else if !overflowed, sliceStart <= UInt64(bytes.count) {
                length = Int(min(available, UInt64(bytes.count) - sliceStart))
            } else { length = 0 }
            guard length <= maximumSnapshotSelectionWork else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "read-bytes exceeds the snapshot byte budget",
                    budget: .init(unit: .bytes, limit: Int64(maximumSnapshotSelectionWork)),
                    used: Int64(length), narrowing: ["count"]))
            }
            let digits = Array("0123456789abcdef".utf8)
            var hex: [UInt8] = []
            hex.reserveCapacity(length * 2)
            for index in 0..<length {
                if index % checkpointInterval == 0 { try checkpoint() }
                let byte: UInt8 = section.isZeroFill ? 0 : bytes[bytes.startIndex + Int(sliceStart) + index]
                hex.append(digits[Int(byte >> 4)])
                hex.append(digits[Int(byte & 15)])
            }
            var fields: [String: ScriptValue] = [
                "address": .hex(target), "length": .count(UInt64(length)),
                "hex": .string(String(decoding: hex, as: UTF8.self)),
            ]
            fields.merge(imageProvenanceFields(slot: slot, snapshot: snapshot)) { _, label in label }
            return .object(fields)

        case "demangle":
            return try demangleReply(arguments)

        default:
            throw ScriptingError.unknownCommand(command)
        }
    }

    /// The shared range scan behind `callers` (call edges INTO the function, `reverse`) and
    /// `callees` (call edges out of it): `call` xrefs whose relevant endpoint lies inside the
    /// function range, deduplicated on `[from, to]`, in index order. `workUsed` is the caller's
    /// consumed budget; `step` charges one unit per visited candidate. Exhausting the shared
    /// work budget throws the typed `budgetExceeded` refusal, never a truncated edge list.
    nonisolated static func visitFunctionCallEdges(
        reverse: Bool, function: FunctionSummary, view: WorkspaceSnapshot, command: String,
        workUsed: Int, checkpoint: () throws -> Void, step: () throws -> Void,
        visit: (XRef) throws -> Void
    ) throws {
        // A one-byte half-open range cannot represent the final UInt64 address.
        let finalAddressOnly = function.startAddress == UInt64.max && function.endAddress <= function.startAddress
        let range = finalAddressOnly ? nil : view.functionRange(function)
        let lower = range?.lowerBound ?? UInt64.max
        let upperInclusive = range.map { $0.upperBound - 1 } ?? UInt64.max
        var seen = Set<[UInt64]>()
        do {
            try view.visitXRefCandidates(reverse ? .to : .from,
                lower: lower, upperInclusive: upperInclusive,
                in: view.primarySlot, maximumCandidates: maximumSnapshotSelectionWork - workUsed,
                checkpoint: checkpoint) { ref in
                try step()
                guard ref.kind == XRefKind.call,
                      (range?.contains(reverse ? ref.to : ref.from)
                        ?? ((reverse ? ref.to : ref.from) == UInt64.max)),
                      seen.insert([ref.from, ref.to]).inserted else { return true }
                try visit(ref)
                return true
            }
        } catch XRefEndpointIndex.SelectionFailure.workBudget {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "\(command) exceeds the snapshot work budget",
                budget: .init(unit: .workSteps, limit: Int64(maximumSnapshotSelectionWork)),
                used: Int64(maximumSnapshotSelectionWork + 1), narrowing: []))
        }
    }
}
