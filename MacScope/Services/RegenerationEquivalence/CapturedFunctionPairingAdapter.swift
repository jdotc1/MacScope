import Foundation

/// RG6 projects only captured raw symbols and extents. The full fingerprint adapter would
/// compute new body/CFG digests and inspect unrelated analysis arrays; none are needed here.
extension FunctionVersionFingerprintAdapter {
    static func capturedSymbolFingerprints(functions: [FunctionSummary], symbols: [SymbolSummary],
                                           budget: RegenerationWorkBudget) throws -> [FunctionVersionFingerprint] {
        try FunctionPairingProjection.validateCounts(functions: functions.count, symbols: symbols.count, budget: budget)
        var remainingBytes = min(budget.maximumInputBytes, 1_024 * 1_024)
        var namesByStart: [UInt64: Set<String>] = [:]
        for symbol in symbols {
            try budget.checkpoint()
            guard let address = symbol.address, let name = symbol.rawLinkageName else { continue }
            let bytes = name.utf8.count
            guard bytes <= 1_024, bytes <= remainingBytes else { throw RegenerationWorkBudgetError.inputLimitExceeded }
            remainingBytes -= bytes
            // Absolute/indirect symbol values are not addresses of section definitions.
            guard symbol.kind == "local" || symbol.kind == "export" else { continue }
            // Keep every spelling until ambiguity is resolved, including unknown placeholders.
            namesByStart[address, default: []].insert(name)
        }
        var ambiguousNames = Set<String>()
        for function in functions {
            try budget.checkpoint()
            let names = namesByStart[function.startAddress] ?? []
            if names.count > 1 { ambiguousNames.formUnion(names) }
        }
        return try functions.map { function in
            try budget.checkpoint()
            guard function.endAddress >= function.startAddress else { throw EquivalenceCaptureError.invalidFunctionExtent }
            let names = namesByStart[function.startAddress] ?? []
            let name = names.count == 1 ? names.first.flatMap { ambiguousNames.contains($0) ? nil : $0 } : nil
            return FunctionVersionFingerprint(id: function.id.uuidString, address: function.startAddress,
                symbolName: name.flatMap { FunctionPairingProjection.meaningfulSymbol($0) },
                size: function.endAddress - function.startAddress)
        }
    }
}
