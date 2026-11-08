import Foundation

/// Pairing and size evidence are descriptive; they do not certify equivalent behavior.
struct PairingProjection: Codable, Sendable {
    let matches: [FunctionVersionMatch]
    let removedIDs: [String]
    let addedIDs: [String]
    let unresolved: [FunctionVersionUnresolvedGroup]
    let originalSizes: [UInt64]
    let rebuiltSizes: [UInt64]
    let assessedEvidence: [String]
    let unassessedEvidence: [String]
}

enum FunctionPairingProjection {
    // The existing matcher is synchronous. Limit this symbol-only pass before entering it;
    // cancellation/deadline checks surround it, but do not preempt a single matcher call.
    static let maximumFunctions = 4_096
    static let maximumSymbols = 16_384

    static func validateCounts(functions: Int, symbols: Int = 0, budget: RegenerationWorkBudget) throws {
        try budget.checkpoint()
        guard functions <= maximumFunctions, symbols <= maximumSymbols,
              functions <= budget.maximumRecords, symbols <= budget.maximumRecords - functions else {
            throw RegenerationWorkBudgetError.recordLimitExceeded
        }
    }

    static func meaningfulSymbol(_ name: String) -> String? {
        guard !FunctionVersionFingerprinting.isGeneratedName(name),
              !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !["unknown", "<unknown>", "???", "?"].contains(name.lowercased()),
              !(name.hasPrefix("0x") && name.dropFirst(2).allSatisfy(\.isHexDigit)) else { return nil }
        return name
    }

    static func compare(original: [FunctionVersionFingerprint], rebuilt: [FunctionVersionFingerprint],
                        budget suppliedBudget: RegenerationWorkBudget? = nil) throws -> PairingProjection {
        let budget = try suppliedBudget ?? .start()
        try validateCounts(functions: original.count + rebuilt.count, budget: budget)
        var remainingBytes = min(budget.maximumInputBytes, 1_024 * 1_024)
        func symbolOnly(_ functions: [FunctionVersionFingerprint]) throws -> [FunctionVersionFingerprint] {
            try functions.map { function in
                try budget.checkpoint()
                let bytes = function.id.utf8.count + (function.symbolName?.utf8.count ?? 0)
                guard bytes <= 2_048, bytes <= remainingBytes else { throw RegenerationWorkBudgetError.inputLimitExceeded }
                remainingBytes -= bytes
                return FunctionVersionFingerprint(id: function.id, address: function.address,
                    symbolName: function.symbolName.flatMap(meaningfulSymbol), size: function.size)
            }
        }
        let old = try symbolOnly(original), new = try symbolOnly(rebuilt)
        try budget.checkpoint()
        let matcher = try FunctionVersionMatcher(old: old, new: new)
        try budget.checkpoint()
        let matched = try matcher.match()
        try budget.checkpoint()
        return .init(matches: matched.matches, removedIDs: matched.removedIDs, addedIDs: matched.addedIDs,
                     unresolved: matched.unresolved, originalSizes: original.map(\.size).sorted(),
                     rebuiltSizes: rebuilt.map(\.size).sorted(),
                     assessedEvidence: ["Unique captured raw symbol names; duplicate candidates remain unresolved.", "Captured function extent sizes (descriptive)."],
                     unassessedEvidence: ["Body, control flow, callees and string references.",
                         "Missing raw symbols and competing bindings remain unpaired; display names are not identity.",
                         "Function discovery completeness; unpaired does not prove added or removed code.",
                         "Behavioral equivalence and reconstruction acceptance; equal sizes do not establish unchanged code."])
    }
}
