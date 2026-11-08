import Foundation

extension WorkspaceScriptingAPI {
    nonisolated static let maximumInstructionPreviewBytes = 256

    /// Opt-in metadata only. Selection, disassembly text and authored comments are unchanged.
    nonisolated static func annotatedInstructionObjects(
        _ rows: [InstructionRow], snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void
    ) throws -> [ScriptValue] {
        guard !rows.isEmpty else { return [] }
        let slot = snapshot.primarySlot
        // Register branches/calls have no direct target here. A same-source data xref
        // must not turn their register operands into a claimed data/call target.
        let indirectBranchMnemonics: Set<String> = [
            "br", "braa", "brab", "braaz", "brabz",
            "blr", "blraa", "blrab", "blraaz", "blrabz",
        ]
        var objects: [ScriptValue] = []
        objects.reserveCapacity(rows.count)
        var nonCallAddresses = Set<UInt64>()
        var calls: [Int: UInt64] = [:]
        var callTargets = Set<UInt64>()
        var lowest = UInt64.max
        var highest: UInt64 = 0
        for (index, row) in rows.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            objects.append(instructionObject(row, snapshot))
            lowest = min(lowest, row.address)
            highest = max(highest, row.address)
            if BranchTargetSymbolizer.callMnemonics.contains(row.mnemonic.lowercased()) {
                let token = row.operands.split(separator: ",").last.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
                if let target = BranchTargetSymbolizer.parseHexAddress(token) {
                    calls[index] = target
                    callTargets.insert(target)
                }
            } else if !indirectBranchMnemonics.contains(row.mnemonic.lowercased()) {
                nonCallAddresses.insert(row.address)
            }
        }
        var dataBySource: [UInt64: XRef] = [:]
        var dataTargets = Set<UInt64>()
        var suppressed = Set<XRefEndpointKey>()
        for (index, edit) in snapshot.manualXRefs.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            guard edit.imageSlot == slot, edit.isSuppression, nonCallAddresses.contains(edit.from) else { continue }
            suppressed.insert(edit.endpointKey)
        }
        func selectData(_ ref: XRef) {
            let key = XRefEndpointKey(from: ref.from, to: ref.to, kind: ref.kind)
            guard ref.kind != XRefKind.call, nonCallAddresses.contains(ref.from),
                  !suppressed.contains(key), dataBySource[ref.from] == nil else { return }
            dataBySource[ref.from] = ref
            dataTargets.insert(ref.to)
        }
        for (index, ref) in try snapshot.xrefCandidates(.from, lower: lowest,
            upperInclusive: highest, in: slot, checkpoint: checkpoint).enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            selectData(ref)
        }
        for (index, edit) in snapshot.manualXRefs.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            guard edit.imageSlot == slot, !edit.isSuppression else { continue }
            selectData(XRef(id: edit.id, from: edit.from, to: edit.to, kind: edit.kind))
        }
        let targets = callTargets.union(dataTargets)
        let names = targets.isEmpty ? [:] : snapshot.branchTargetNames(in: slot, restrictedTo: targets)
        let describer: DataTargetDescriber?
        if dataTargets.isEmpty {
            describer = nil
        } else {
            describer = try DataTargetDescriber(snapshot: snapshot, slot: slot, targets: dataTargets,
                includeCFStringStorage: false, checkpoint: checkpoint)
        }
        func targetName(_ target: UInt64) -> String? {
            names[target].flatMap { $0.isEmpty ? nil : $0 }
        }
        func preview(_ text: String, fields: inout [String: ScriptValue]) throws {
            let length = text.utf8.count
            guard length > maximumInstructionPreviewBytes else { fields["value"] = .string(text); return }
            var prefix = ""
            var bytes = 0
            for (index, scalar) in text.unicodeScalars.enumerated() {
                if index % checkpointInterval == 0 { try checkpoint() }
                let size = String(scalar).utf8.count
                guard bytes + size <= maximumInstructionPreviewBytes else { break }
                prefix.unicodeScalars.append(scalar)
                bytes += size
            }
            fields["value"] = .string(prefix)
            fields["valueTruncated"] = .bool(true)
            fields["valueByteLength"] = .int(Int64(length))
        }
        for (index, row) in rows.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            guard case .object(var fields) = objects[index] else { continue }
            if BranchTargetSymbolizer.callMnemonics.contains(row.mnemonic.lowercased()) {
                if let target = calls[index], let name = targetName(target) {
                    fields["to"] = .hex(target)
                    fields["kind"] = .string(XRefKind.call)
                    fields["toName"] = .string(name)
                    let prefix = "_objc_msgSend$"
                    if name.hasPrefix(prefix), name.count > prefix.count {
                        fields["selector"] = .string(String(name.dropFirst(prefix.count)))
                    }
                    if let demangled = scriptingDemangled(name) { fields["toDemangled"] = .string(demangled) }
                }
            } else if !indirectBranchMnemonics.contains(row.mnemonic.lowercased()),
                      let ref = dataBySource[row.address] {
                let name = targetName(ref.to)
                fields["to"] = .hex(ref.to)
                fields["kind"] = .string(ref.kind)
                if let name { fields["toName"] = .string(name) }
                if let describer {
                    let description = describer.describe(ref, named: name != nil)
                    if let targetKind = description["targetKind"] { fields["targetKind"] = targetKind }
                    if let value = description["value"] {
                        if case .string(let text) = value { try preview(text, fields: &fields) }
                        else { fields["value"] = value }
                    }
                }
            }
            objects[index] = .object(fields)
        }
        return objects
    }
}
