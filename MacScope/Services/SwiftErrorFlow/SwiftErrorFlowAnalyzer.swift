// Deliberately smaller than AIRS swift-sync-error-edges-v16. No file/process I/O,
// runtime execution, CFG reachability, dominance, error-region or return-choice model.
public enum SwiftErrorFlowAnalyzer {
    public static let model = SwiftErrorFlowModel.nativeV1.rawValue
    public static func analyze(_ input: SwiftErrorFlowRequest,
                               model: SwiftErrorFlowModel = .nativeV1) -> SwiftErrorFlowReport {
        func reject(_ code: String) -> SwiftErrorFlowReport {
            .init(model: model, status: .rejected, slice: input.slice, declarations: [], edges: [], abstentions: [.init(code: code, address: nil)])
        }
        guard input.code.words.count <= 65_536, input.functions.count <= 4_096,
              input.symbols.count <= 8_192 else { return reject("input_budget_exceeded") }
        guard input.slice.cpuType == 0x0100000c, input.slice.cpuSubtype == 0,
              input.slice.littleEndian else { return reject("unsupported_architecture") }
        guard input.slice.artifactSHA256.utf8.count == 64 else { return reject("invalid_slice_identity") }
        let hash = Array(input.slice.artifactSHA256.utf8)
        guard hash.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              input.slice.sliceByteCount > 0,
              !input.slice.sliceOffset.addingReportingOverflow(input.slice.sliceByteCount).overflow
        else { return reject("invalid_slice_identity") }
        guard !input.code.hasEmbeddedData, !input.code.hasRelocations
        else { return reject("tainted_code_mapping") }
        let byteCount = UInt64(input.code.words.count) * 4
        let mappedEnd = input.code.baseAddress.addingReportingOverflow(byteCount)
        let fileEnd = input.code.sliceRelativeFileOffset.addingReportingOverflow(byteCount)
        guard !input.code.words.isEmpty, input.code.sectionOrdinal > 0,
              input.code.baseAddress % 4 == 0, input.code.sliceRelativeFileOffset % 4 == 0,
              !mappedEnd.overflow, !fileEnd.overflow, fileEnd.partialValue <= input.slice.sliceByteCount
        else { return reject("invalid_code_mapping") }
        guard input.symbols.allSatisfy({ $0.name.utf8.count <= 512 }) else { return reject("symbol_budget_exceeded") }
        let functions = input.functions.sorted { $0.start < $1.start }
        var previousEnd = input.code.baseAddress
        for f in functions {
            guard f.boundarySource == "lc_function_starts", f.start % 4 == 0, f.endExclusive % 4 == 0,
                  f.start >= previousEnd, f.endExclusive > f.start, f.endExclusive <= mappedEnd.partialValue
            else { return reject("unproven_or_invalid_function_boundary") }
            previousEnd = f.endExclusive
        }
        let entries = Set(functions.map(\.start))
        var symbolGroups: [UInt64: [SwiftErrorFlowSymbol]] = [:]
        for symbol in input.symbols where entries.contains(symbol.address) {
            // Retain all defined aliases, including local/private aliases, before
            // deciding whether the sole record is an exact external declaration.
            if symbol.nType & 0xe0 == 0, symbol.nType & 0x0e == 0x0e,
               symbol.sectionOrdinal == input.code.sectionOrdinal {
                symbolGroups[symbol.address, default: []].append(symbol)
            }
        }
        var declarations: [SwiftErrorFlowDeclaration] = []
        for f in functions {
            guard let group = symbolGroups[f.start], group.count == 1,
                  let symbol = group.first, symbol.nType == 0x0f, symbol.nDesc & 0x300 == 0,
                  let declaration = Self.declaration(symbol) else { continue }
            declarations.append(declaration)
        }
        let byAddress = Dictionary(uniqueKeysWithValues: declarations.map { ($0.address, $0) })
        var edges: [SwiftErrorFlowEdge] = []
        var abstentions: [SwiftErrorFlowAbstention] = []
        for function in functions {
            let first = Int((function.start - input.code.baseAddress) / 4)
            let end = Int((function.endExclusive - input.code.baseAddress) / 4)
            for index in first..<end {
                let word = input.code.words[index]
                guard word & 0xfc000000 == 0x94000000 else { continue }
                let pc = input.code.baseAddress + UInt64(index) * 4
                let raw = Int64(word & 0x03ffffff)
                let delta = (raw & 0x02000000 == 0 ? raw : raw - 0x04000000) * 4
                guard let target = adding(pc, delta), entries.contains(target) else {
                    abstentions.append(.init(code: "callee_not_exact_mapped_entry", address: pc)); continue
                }
                guard let callee = byAddress[target] else {
                    abstentions.append(.init(code: "callee_declaration_absent_ambiguous_or_unsupported", address: pc)); continue
                }
                switch observe(input.code, function, index, end, callee, model: model) {
                case .edge(let edge): edges.append(edge)
                case .abstain(let reason): abstentions.append(.init(code: reason, address: pc))
                }
            }
        }
        return .init(model: model, status: .analyzed, slice: input.slice, declarations: declarations, edges: edges, abstentions: abstentions)
    }

    private enum Observation { case edge(SwiftErrorFlowEdge), abstain(String) }
    private static func observe(_ code: SwiftErrorFlowCode, _ function: SwiftErrorFlowFunction,
                                _ callIndex: Int, _ end: Int, _ callee: SwiftErrorFlowDeclaration,
                                model: SwiftErrorFlowModel) -> Observation {
        var comparison: UInt64?
        var aliases: Set<UInt32> = [21]
        var testedRegister: UInt32 = 21
        let callPC = code.baseAddress + UInt64(callIndex) * 4
        let stop = min(end, callIndex + 9) // at most eight words after BL
        for index in (callIndex + 1)..<stop {
            let word = code.words[index]
            let pc = code.baseAddress + UInt64(index) * 4
            var zeroTarget = false
            var kind = ""
            if comparison != nil {
                // Exact B.EQ / B.NE only; bit 4 and reserved bit 24 must be zero.
                guard word & 0xff00001e == 0x54000000 else {
                    return .abstain("comparison_branch_not_adjacent_or_supported")
                }
                zeroTarget = word & 1 == 0
                kind = zeroTarget ? "cmp_zero_b_eq" : "cmp_zero_b_ne"
            } else {
                if word == 0xd503201f { continue }
                if model == .registerCopiesV2 {
                    // Exact MOV Xd,Xm (ORR Xd,XZR,Xm, LSL #0). No W/SP/shifted forms.
                    // Semantics ported from AIRS f52d333, swift_error_flow._edges.
                    if word & 0xffe0ffe0 == 0xaa0003e0 {
                        let destination = word & 31
                        let source = (word >> 16) & 31
                        if destination != 31 {
                            if aliases.contains(source) { aliases.insert(destination) }
                            else { aliases.remove(destination) }
                        }
                        guard !aliases.isEmpty else { return .abstain("error_value_clobbered") }
                        continue
                    }
                    // Exact unshifted CMP Xn,#0; adjacent EQ/NE is required above.
                    if word & 0xfffffc1f == 0xf100001f {
                        testedRegister = (word >> 5) & 31
                        guard aliases.contains(testedRegister) else {
                            return .abstain("not_error_result_comparison")
                        }
                        comparison = pc
                        continue
                    }
                } else if word == 0xf10002bf { comparison = pc; continue }
                // Exact 64-bit CBZ/CBNZ. Native-v1 remains restricted to X21.
                let mask: UInt32 = model == .nativeV1 ? 0xfe00001f : 0xfe000000
                let expected: UInt32 = model == .nativeV1 ? 0xb4000015 : 0xb4000000
                guard word & mask == expected else {
                    return .abstain("intervening_instruction_or_test_unsupported")
                }
                testedRegister = word & 31
                guard aliases.contains(testedRegister) else { return .abstain("not_error_result_test") }
                zeroTarget = word & 0x01000000 == 0
                kind = "\(zeroTarget ? "cbz" : "cbnz")_x\(testedRegister)"
            }
            let raw = Int64((word >> 5) & 0x7ffff)
            let delta = (raw & 0x40000 == 0 ? raw : raw - 0x80000) * 4
            guard let target = adding(pc, delta), let fallthroughAddress = adding(pc, 4),
                  target > pc, target != fallthroughAddress, target % 4 == 0,
                  target >= function.start, target < function.endExclusive,
                  fallthroughAddress >= function.start, fallthroughAddress < function.endExclusive else {
                return .abstain("unsupported_successor_region")
            }
            let success = zeroTarget ? target : fallthroughAddress
            let error = zeroTarget ? fallthroughAddress : target
            return .edge(.init(callerStart: function.start, callAddress: callPC, calleeAddress: callee.address,
                               symbol: callee.symbol, testAddress: pc, comparisonAddress: comparison,
                               successAddress: success, errorAddress: error,
                               callOffset: callPC - function.start, testOffset: pc - function.start,
                               successOffset: success - function.start, errorOffset: error - function.start,
                               testKind: kind, evidenceWords: Array(code.words[callIndex...index]),
                               testedRegister: model == .registerCopiesV2 ? UInt8(testedRegister) : nil))
        }
        return .abstain(comparison == nil ? "postcall_window_exhausted" : "comparison_branch_missing_or_outside_window")
    }

    private static func adding(_ address: UInt64, _ delta: Int64) -> UInt64? {
        if delta >= 0 {
            let result = address.addingReportingOverflow(UInt64(delta))
            return result.overflow ? nil : result.partialValue
        }
        // All callers supply bounded A64 imm26/imm19 offsets (never Int64.min).
        let magnitude = UInt64(-delta)
        return address >= magnitude ? address - magnitude : nil
    }

    private static func declaration(_ symbol: SwiftErrorFlowSymbol) -> SwiftErrorFlowDeclaration? {
        var bytes = Array(symbol.name.utf8)
        if bytes.starts(with: [95, 36, 115]) { bytes.removeFirst() }
        guard bytes.count <= 512, bytes.starts(with: [36, 115]) else { return nil }
        var cursor = 2
        var names: [String] = []
        for _ in 0..<2 {
            guard cursor < bytes.count, (49...57).contains(bytes[cursor]) else { return nil }
            var size = 0; var digits = 0
            while cursor < bytes.count, (48...57).contains(bytes[cursor]) {
                digits += 1
                guard digits <= 3 else { return nil }
                size = size * 10 + Int(bytes[cursor] - 48); cursor += 1
            }
            guard size <= 128, cursor + size <= bytes.count else { return nil }
            let identifier = Array(bytes[cursor..<(cursor + size)])
            guard let first = identifier.first, asciiLetter(first) || first == 95,
                  identifier.allSatisfy({ asciiLetter($0) || $0 == 95 || (48...57).contains($0) }) else { return nil }
            names.append(String(decoding: identifier, as: UTF8.self)); cursor += size
        }
        let suffix = String(decoding: bytes[cursor...], as: UTF8.self)
        let parameters: [String]; let result: String
        switch suffix {
        case "yS2iKF": parameters = ["Swift.Int"]; result = "Swift.Int"
        case "yySiKF": parameters = ["Swift.Int"]; result = "Swift.Void"
        case "yyKF": parameters = []; result = "Swift.Void"
        case "SiyKF": parameters = []; result = "Swift.Int"
        default: return nil
        }
        return .init(address: symbol.address, symbol: symbol.name, module: names[0], name: names[1], parameters: parameters, result: result)
    }
    private static func asciiLetter(_ byte: UInt8) -> Bool { (65...90).contains(byte) || (97...122).contains(byte) }
}
