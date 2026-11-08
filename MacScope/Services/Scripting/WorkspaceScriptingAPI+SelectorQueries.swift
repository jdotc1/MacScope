import Foundation

extension WorkspaceScriptingAPI {
    /// Upper bound on control-flow edges the `callers` selector query scans for direct branches to a stub.
    nonisolated static let maximumSelectorBranchEdgeScan = 8_000_000

    nonisolated static func selectorArgument(_ arguments: ScriptValue) throws -> String? {
        guard let value = arguments["selector"], value != .null else { return nil }
        guard let selector = value.stringValue,
              !selector.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              selector.utf8.count <= 1_024 else {
            throw ScriptingError.invalidArgument("selector must be a non-empty string of at most 1024 UTF-8 bytes")
        }
        if let function = arguments["function"], function != .null {
            throw ScriptingError.invalidArgument("selector cannot be combined with function or address")
        }
        if let address = arguments["address"], address != .null {
            throw ScriptingError.invalidArgument("selector cannot be combined with function or address")
        }
        return selector
    }

    nonisolated static func selectorsArgument(_ arguments: ScriptValue) throws -> [String]? {
        guard let value = arguments["selectors"], value != .null else { return nil }
        let message = "selectors must be an array of 1 to 8 distinct non-empty strings of at most 1024 UTF-8 bytes"
        guard case .array(let items) = value, (1...8).contains(items.count) else {
            throw ScriptingError.invalidArgument(message)
        }
        var selectors: [String] = []
        var distinct = Set<String>()
        for item in items {
            guard let selector = item.stringValue,
                  !selector.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  selector.utf8.count <= 1_024,
                  distinct.insert(selector).inserted else {
                throw ScriptingError.invalidArgument(message)
            }
            selectors.append(selector)
        }
        for key in ["selector", "function", "address"] {
            if let other = arguments[key], other != .null {
                throw ScriptingError.invalidArgument("selectors cannot be combined with selector, function or address")
            }
        }
        return selectors
    }

    nonisolated static func selectorSendSiteRows(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        selectionWorkLimit: Int = maximumSnapshotSelectionWork, resultLimit: Int = maximumSnapshotRows,
        branchEdgeScanLimit: Int = maximumSelectorBranchEdgeScan,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        let selectorList: [String]
        if let list = try selectorsArgument(arguments) {
            selectorList = list
        } else if let selector = try selectorArgument(arguments) {
            selectorList = [selector]
        } else {
            throw ScriptingError.missingArgument("selector")
        }
        let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
        let slot = filter ?? snapshot.primarySlot
        guard let analysis = snapshot.analysis(in: slot) else { return .array([]) }
        let workLimit = max(0, min(selectionWorkLimit, maximumSnapshotSelectionWork))
        let rowLimit = max(0, min(resultLimit, maximumSnapshotRows))
        var work = 0
        func workFailure(_ used: Int? = nil) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "callers selector exceeds the snapshot work budget",
                budget: .init(unit: .workSteps, limit: Int64(workLimit)),
                used: used.map { Int64($0) }, narrowing: ["imageSlot"]))
        }
        func rowFailure(_ used: Int? = nil) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "callers selector exceeds the snapshot result budget",
                budget: .init(unit: .rows, limit: Int64(rowLimit)),
                used: used.map { Int64($0) }, narrowing: ["imageSlot"]))
        }
        func step() throws {
            guard work < workLimit else { throw workFailure(work + 1) }
            if work % checkpointInterval == 0 { try checkpoint() }
            work += 1
        }
        try checkpoint()
        var selected: [(ref: XRef, via: String, selector: String)] = []
        for selector in selectorList {
            let stubName = "_objc_msgSend$" + selector
            var stubs = Set<UInt64>()
            for symbol in analysis.symbols {
                try step()
                if symbol.name == stubName, let address = symbol.address { stubs.insert(address) }
            }
            for function in analysis.functions {
                try step()
                if function.name == stubName { stubs.insert(function.startAddress) }
            }
            var slots = Set<UInt64>()
            for (address, name) in analysis.objcSelectors {
                try step()
                if name == selector { slots.insert(address) }
            }
            guard !stubs.isEmpty || !slots.isEmpty else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .unknownSubject,
                    detail: "No Objective-C selector named '\(String(selector.prefix(1_024)))' in image slot \(slot.rawValue): no _objc_msgSend$ stub and no selector reference.",
                    field: "selector"))
            }
            var seen = Set<[UInt64]>()
            func query(_ target: UInt64, via: String) throws {
                try step()
                let refs: [XRef]
                do {
                    refs = try snapshot.boundedEffectiveXRefs(.to(target), in: slot, limit: nil,
                        maximumRows: rowLimit - selected.count, maximumWork: workLimit - work,
                        including: { ref in
                            if via == "stub" {
                                guard ref.kind == XRefKind.call else { return false }
                            } else {
                                guard ref.kind == XRefKind.selref else { return false }
                                if snapshot.section(containing: ref.from, in: slot)?.name.split(separator: ",").last == "__objc_stubs" { return false }
                            }
                            return seen.insert([ref.from, ref.to]).inserted
                        }, chargeWork: step, checkpoint: checkpoint)
                } catch WorkspaceSnapshot.XRefQueryFailure.workBudget { throw workFailure() }
                  catch WorkspaceSnapshot.XRefQueryFailure.resultBudget { throw rowFailure() }
                for (index, ref) in refs.enumerated() {
                    if index % checkpointInterval == 0 { try checkpoint() }
                    selected.append((ref, via, selector))
                }
            }
            for target in stubs.sorted() { try query(target, via: "stub") }
            // A direct branch (`b`, `b.cond`, `cbz`, `tbz`) to the stub is a `branch` control-flow edge, not a
            // `call` xref. Own counter: the shared work budget and its exact-budget tests stay unchanged.
            if !stubs.isEmpty, !analysis.controlFlowEdges.isEmpty {
                let edges = analysis.controlFlowEdges
                guard edges.count <= branchEdgeScanLimit else {
                    throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                        detail: "callers selector branch scan exceeds the control-flow edge budget",
                        budget: .init(unit: .workSteps, limit: Int64(branchEdgeScanLimit)),
                        used: Int64(edges.count), narrowing: ["imageSlot"]))
                }
                var suppressed = Set<[UInt64]>()
                for manual in snapshot.manualXRefs
                where manual.isSuppression && manual.imageSlot == slot && manual.kind == XRefKind.call && stubs.contains(manual.to) {
                    suppressed.insert([manual.from, manual.to])
                }
                for (index, edge) in edges.enumerated() {
                    if index % checkpointInterval == 0 { try checkpoint() }
                    guard edge.kind == "branch", stubs.contains(edge.to),
                          !suppressed.contains([edge.from, edge.to]),
                          snapshot.section(containing: edge.from, in: slot)?.name.split(separator: ",").last != "__objc_stubs",
                          seen.insert([edge.from, edge.to]).inserted else { continue }
                    guard selected.count < rowLimit else { throw rowFailure() }
                    selected.append((XRef(id: UUID(), from: edge.from, to: edge.to, kind: XRefKind.call), "stubBranch", selector))
                }
            }
            for target in slots.sorted() { try query(target, via: "selref") }
        }
        selected.sort {
            if $0.ref.from != $1.ref.from { return $0.ref.from < $1.ref.from }
            if $0.ref.to != $1.ref.to { return $0.ref.to < $1.ref.to }
            return $0.selector < $1.selector
        }
        let named = try namedGraphRows(selected.map(\.ref), includeKind: false,
            snapshot: snapshot, slot: slot, checkpoint: checkpoint)
        var rows: [ScriptValue] = []
        for (index, value) in named.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            if case .object(var fields) = value {
                fields["selector"] = .string(selected[index].selector)
                fields["via"] = .string(selected[index].via)
                rows.append(.object(fields))
            }
        }
        return .array(rows)
    }

    nonisolated static func selectorImplementationRows(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        selectionWorkLimit: Int = maximumSnapshotSelectionWork, resultLimit: Int = maximumSnapshotRows,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        guard let selector = try selectorArgument(arguments) else { throw ScriptingError.missingArgument("selector") }
        let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
        let slot = filter ?? snapshot.primarySlot
        guard let analysis = snapshot.analysis(in: slot) else { return .array([]) }
        let workLimit = max(0, min(selectionWorkLimit, maximumSnapshotSelectionWork))
        let rowLimit = max(0, min(resultLimit, maximumSnapshotRows))
        var work = 0
        var matches: [(owner: String, category: String?, method: ObjCMethod)] = []
        func step() throws {
            guard work < workLimit else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "implementations exceeds the snapshot work budget",
                    budget: .init(unit: .workSteps, limit: Int64(workLimit)),
                    used: Int64(work + 1), narrowing: ["imageSlot"]))
            }
            if work % checkpointInterval == 0 { try checkpoint() }
            work += 1
        }
        func methods(_ methods: [ObjCMethod], owner: String, category: String?) throws {
            for method in methods {
                try step()
                guard method.selector == selector else { continue }
                guard matches.count < rowLimit else {
                    throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                        detail: "implementations exceeds the snapshot result budget",
                        budget: .init(unit: .rows, limit: Int64(rowLimit)),
                        used: Int64(matches.count + 1), narrowing: ["imageSlot"]))
                }
                matches.append((owner, category, method))
            }
        }
        try checkpoint()
        for cls in analysis.objcClasses {
            try step()
            try methods(cls.instanceMethods, owner: cls.name, category: nil)
            try methods(cls.classMethods, owner: cls.name, category: nil)
        }
        for category in analysis.objcCategories {
            try step()
            try methods(category.instanceMethods, owner: category.className, category: category.name)
            try methods(category.classMethods, owner: category.className, category: category.name)
        }
        matches.sort {
            if $0.owner != $1.owner { return $0.owner < $1.owner }
            if $0.category != $1.category {
                guard let left = $0.category else { return true }
                guard let right = $1.category else { return false }
                return left < right
            }
            if $0.method.isClassMethod != $1.method.isClassMethod { return !$0.method.isClassMethod }
            switch ($0.method.implementation, $1.method.implementation) {
            case (nil, .some): return true
            case (.some, nil): return false
            case let (.some(left), .some(right)): return left < right
            case (nil, nil): return false
            }
        }
        let names = try boundedGraphTargetNames(matches.compactMap { $0.method.implementation },
                                                snapshot: snapshot, slot: slot, checkpoint: checkpoint)
        var rows: [ScriptValue] = []
        for (index, match) in matches.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            rows.append(.object([
                "class": .string(match.owner), "category": match.category.map(ScriptValue.string) ?? .null,
                "isClassMethod": .bool(match.method.isClassMethod), "selector": .string(selector),
                "address": match.method.implementation.map(ScriptValue.hex) ?? .null,
                "name": match.method.implementation.flatMap { names[$0] }.map(ScriptValue.string) ?? .null,
                "imageSlot": .int(Int64(slot.rawValue)),
            ]))
        }
        try checkpoint()
        return .array(rows)
    }
}
