import Foundation

extension WorkspaceScriptingAPI {
    /// Warm graph enrichment reads only selected addresses from the image-owned index.
    /// A refused index never becomes an apparently complete row with missing names.
    nonisolated static func boundedGraphTargetNames(
        _ addresses: [UInt64], snapshot: WorkspaceSnapshot, slot: ImageSlot,
        checkpoint: () throws -> Void
    ) throws -> [UInt64: String] {
        guard !addresses.isEmpty else { return [:] }
        do {
            guard addresses.count <= 100_000 else { throw GraphNameIndex.Limit.rows }
            guard let analysis = snapshot.analysis(in: slot) else { try checkpoint(); return [:] }
            let index = try analysis.graphNames.index(functions: analysis.functions, symbols: analysis.symbols,
                                                       checkpoint: checkpoint)
            var result: [UInt64: String] = [:], remaining = 16 << 20
            for (position, address) in addresses.enumerated() {
                if position.isMultiple(of: checkpointInterval) { try checkpoint() }
                guard let raw = index.rawName(address) else { continue }
                let name = try graphAdmittedText(snapshot.displayName(at: address, in: slot, default: raw),
                                                 remaining: &remaining, checkpoint: checkpoint)
                result[address] = name
            }
            try checkpoint(); return result
        } catch let failure as GraphNameIndex.Limit { throw graphNameRefusal(failure) }
    }

    nonisolated static func graphNameRefusal(_ failure: GraphNameIndex.Limit) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "Graph name enrichment refused (\(failure)); no partial rows returned.", narrowing: ["imageSlot"]))
    }

    nonisolated private static func graphAdmittedText(_ value: String, remaining: inout Int,
                                                     checkpoint: () throws -> Void) throws -> String {
        var bytes: [UInt8] = []
        for byte in value.utf8 {
            guard bytes.count < 8192 else { throw GraphNameIndex.Limit.name }
            if bytes.count.isMultiple(of: 256) { try checkpoint() }
            bytes.append(byte)
        }
        guard bytes.count <= remaining else { throw GraphNameIndex.Limit.text }
        remaining -= bytes.count
        return String(decoding: bytes, as: UTF8.self)
    }

    nonisolated static func namedGraphRows(
        _ refs: [XRef], includeKind: Bool, snapshot: WorkspaceSnapshot, slot: ImageSlot,
        checkpoint: () throws -> Void, admission: FunctionFactsAdmission? = nil
    ) throws -> [ScriptValue] {
        guard !refs.isEmpty else { return [] }
        do {
            guard refs.count <= 100_000 else { throw GraphNameIndex.Limit.rows }
            let index: GraphNameIndex?
            if let analysis = snapshot.analysis(in: slot) {
                try admission?.graphInputs(analysis)
                index = try analysis.graphNames.index(functions: analysis.functions, symbols: analysis.symbols,
                                                       checkpoint: checkpoint)
            } else { index = nil }
            var remaining = 16 << 20, result: [ScriptValue] = []
            var demangled: [String: String] = [:], attempted = Set<String>()
            func text(_ value: String) throws -> String {
                try admission?.observeText(value, maximum: FunctionFactsAdmission.maximumNameBytes)
                return try graphAdmittedText(value, remaining: &remaining, checkpoint: checkpoint)
            }
            func nameAndDemangled(_ raw: String) throws -> (String, String?) {
                let name = try text(raw)
                if !attempted.contains(name) {
                    // The existing demangler has its own work/output limit. Reserve
                    // bounded request work before invoking it for a mangled name.
                    if name.hasPrefix("$s") || name.hasPrefix("$S") || name.hasPrefix("_$s")
                        || name.hasPrefix("_$S") || name.hasPrefix("_TtC") {
                        try admission?.visit(8_192)
                    } else { try admission?.visit() }
                    try checkpoint(); attempted.insert(name)
                    if let value = scriptingDemangled(name) { demangled[name] = value }
                    try checkpoint()
                }
                return (name, try demangled[name].map { try text($0) })
            }
            result.reserveCapacity(refs.count)
            for (position, ref) in refs.enumerated() {
                try admission?.visit()
                if position.isMultiple(of: checkpointInterval) { try checkpoint() }
                let owner = index?.owner(ref.from)
                let ownerName = try owner.map { try nameAndDemangled(snapshot.displayName(at: $0.start, in: slot, default: $0.name)) }
                var fields: [String: ScriptValue] = [
                    "from": .hex(ref.from), "to": .hex(ref.to), "imageSlot": .int(Int64(slot.rawValue)),
                    "fromFunction": owner.map { .hex($0.start) } ?? .null,
                    "fromFunctionName": ownerName.map { .string($0.0) } ?? .null,
                ]
                if includeKind { fields["kind"] = .string(try text(ref.kind)) }
                var rawTarget = index?.rawName(ref.to)
                if let admission, let analysis = snapshot.analysis(in: slot) {
                    var preferred: FunctionSummary?
                    for candidate in analysis.functions {
                        try admission.visit()
                        guard candidate.startAddress == ref.to else { continue }
                        if let previous = preferred {
                            if candidate.endAddress < previous.endAddress
                                || (candidate.endAddress == previous.endAddress
                                    && candidate.name.utf8.lexicographicallyPrecedes(previous.name.utf8)) {
                                preferred = candidate
                            }
                        } else { preferred = candidate }
                    }
                    if let preferred { rawTarget = preferred.name }
                }
                let target = try rawTarget.map { try nameAndDemangled(snapshot.displayName(at: ref.to, in: slot, default: $0)) }
                let targetName = target.flatMap { $0.0.isEmpty ? nil : $0.0 }
                fields["toName"] = targetName.map(ScriptValue.string) ?? .null
                if let targetName {
                    let prefix = "_objc_msgSend$"
                    if targetName.hasPrefix(prefix), targetName.count > prefix.count {
                        let suffix = targetName.dropFirst(prefix.count)
                        try admission?.observeText(suffix, maximum: FunctionFactsAdmission.maximumNameBytes)
                        fields["selector"] = .string(try text(String(suffix)))
                    }
                    if let value = target?.1 { fields["toDemangled"] = .string(value) }
                }
                if let value = ownerName?.1 { fields["fromFunctionDemangled"] = .string(value) }
                result.append(.object(fields))
            }
            try checkpoint(); return result
        } catch let failure as GraphNameIndex.Limit { throw graphNameRefusal(failure) }
    }

    /// First containment in function-list order; never substitute a preceding function.
    nonisolated static func graphRowOwners(
        sources: [UInt64], functions: [FunctionSummary],
        guardFunction: (Int) throws -> Void, checkpoint: () throws -> Void
    ) throws -> [FunctionSummary?] {
        let order = sources.indices.sorted { sources[$0] < sources[$1] }
        let sortedSources = order.map { sources[$0] }
        var owners = [FunctionSummary?](repeating: nil, count: sources.count)
        // Successor links remove assigned source positions. Overlapping function ranges
        // never revisit all previously assigned sites, and the first containing row wins.
        var successor = Array(0...sources.count)
        func unassigned(_ position: Int) -> Int {
            var root = position
            while successor[root] != root { root = successor[root] }
            var current = position
            while successor[current] != current {
                let next = successor[current]
                successor[current] = root
                current = next
            }
            return root
        }
        func bound(_ value: UInt64, upper: Bool = false) -> Int {
            var low = 0
            var high = sources.count
            while low < high {
                let middle = low + (high - low) / 2
                if sortedSources[middle] < value || (upper && sortedSources[middle] == value) {
                    low = middle + 1
                } else { high = middle }
            }
            return low
        }
        var assigned = 0
        for (index, function) in functions.enumerated() {
            try guardFunction(index)
            if index % checkpointInterval == 0 { try checkpoint() }
            let lower = bound(function.startAddress)
            let upper = function.endAddress > function.startAddress
                ? bound(function.endAddress) : bound(function.startAddress, upper: true)
            var position = unassigned(lower)
            while position < upper {
                if assigned % checkpointInterval == 0 { try checkpoint() }
                owners[order[position]] = function
                assigned += 1
                let next = unassigned(position + 1)
                successor[position] = next
                position = next
            }
        }
        return owners
    }
}
