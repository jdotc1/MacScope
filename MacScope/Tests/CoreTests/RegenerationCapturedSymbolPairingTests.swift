import Foundation
#if !RG6_PAIRING_STANDALONE
import XCTest
@testable import MacScope

final class RegenerationCapturedSymbolPairingTests: XCTestCase {
    func testCapturedRawSymbolAuthority() throws { try CapturedSymbolPairingScenarios.authority() }
    func testSymbolOnlyAmbiguityAndCoverage() throws { try CapturedSymbolPairingScenarios.coverage() }
    func testPairingWorkLimits() async throws { try await CapturedSymbolPairingScenarios.limits() }
}
#endif

/// Shared by the first small standalone check and the deferred native selectors.
enum CapturedSymbolPairingScenarios {
    struct Failure: Error { let message: String }
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw Failure(message: message) }
    }
    static func function(_ address: UInt64, _ name: String = "display") -> FunctionSummary {
        .init(id: UUID(), name: name, startAddress: address, endAddress: address + 8, confidence: 1)
    }
    static func symbol(_ address: UInt64, _ raw: String?, display: String = "display") -> SymbolSummary {
        .init(id: UUID(), name: display, address: address, kind: "local", libraryName: nil, rawLinkageName: raw)
    }
    static func authority() throws {
        let functions = (1...6).map { function(UInt64($0 * 16), "_same_display") }
        let symbols = [symbol(16, "_real", display: "renamed"), symbol(32, nil, display: "_real"),
                       symbol(49, "_nearby"), symbol(64, "_aliasA"), symbol(64, "_aliasB"),
                       symbol(80, "sub_0x00000050"), symbol(96, "<unknown>")]
        let facts = try FunctionVersionFingerprintAdapter.capturedSymbolFingerprints(
            functions: functions, symbols: symbols, budget: .start())
        try require(facts.map(\.symbolName) == ["_real", nil, nil, nil, nil, nil], "Only exact-start unambiguous raw authority")
        try require(facts.map(\.id) == functions.map { $0.id.uuidString }, "Captured IDs preserved")
        try require(facts.allSatisfy { $0.size == 8 && $0.normalizedBodyHash == nil && $0.cfgShapeHash == nil }, "No body or CFG derivation")
        let hiddenDuplicate = try FunctionVersionFingerprintAdapter.capturedSymbolFingerprints(
            functions: [function(16), function(32)],
            symbols: [symbol(16, "_duplicate"), symbol(32, "_duplicate"), symbol(32, "_alias")], budget: .start())
        try require(hiddenDuplicate.allSatisfy { $0.symbolName == nil }, "Alias must not hide a competing duplicate binding")
        for kind in ["absolute", "indirect", "undefined", "stub", "debug"] {
            var nonDefinition = symbol(16, "_not_a_function")
            nonDefinition.kind = kind
            let excluded = try FunctionVersionFingerprintAdapter.capturedSymbolFingerprints(
                functions: [function(16)], symbols: [nonDefinition], budget: .start())
            try require(excluded[0].symbolName == nil, "Non-definition symbol admitted: " + kind)
        }
        let invalid = FunctionSummary(id: UUID(), name: "bad", startAddress: 20, endAddress: 10, confidence: 1)
        do {
            _ = try FunctionVersionFingerprintAdapter.capturedSymbolFingerprints(functions: [invalid], symbols: [], budget: .start())
            throw Failure(message: "Invalid extent admitted")
        } catch EquivalenceCaptureError.invalidFunctionExtent {}
    }
    static func coverage() throws {
        func f(_ id: String, _ address: UInt64, _ name: String?, _ size: UInt64 = 8) -> FunctionVersionFingerprint {
            .init(id: id, address: address, symbolName: name, size: size, basicBlockCount: 3,
                  edgeCount: 2, cfgShapeHash: id, normalizedBodyHash: "shared-body", instructionCount: 4,
                  calleeIDs: [], importedCalleeNames: ["_puts"])
        }
        let original = [f("o1", 10, "_unique"), f("o2", 20, "_duplicate"), f("o3", 30, "_duplicate"),
                        f("o4", 40, nil), f("o5", 50, "sub_0x50"), f("o6", 60, "unknown"), f("o7", 70, "_sameSize")]
        let rebuilt = [f("n1", 100, "_unique", 12), f("n2", 200, "_duplicate"), f("n4", 400, nil),
                       f("n5", 50, "sub_0x50"), f("n6", 60, "unknown"), f("n7", 700, "_sameSize")]
        let result = try FunctionPairingProjection.compare(original: original, rebuilt: rebuilt, budget: .start())
        try require(result.matches.map(\.oldID) == ["o1", "o7"], "Only unique meaningful symbol pairs")
        try require(result.matches.allSatisfy { $0.basis == .symbolName }, "No body/CFG or same-address matching")
        try require(result.matches[0].differences == [.size] && result.matches[1].differences.isEmpty, "Only descriptive size compared")
        try require(result.unresolved.count == 1 && result.unresolved[0].oldIDs == ["o2", "o3"] && result.unresolved[0].newIDs == ["n2"], "Duplicate ambiguity retained")
        try require(Set(result.removedIDs) == Set(["o4", "o5", "o6"]) && Set(result.addedIDs) == Set(["n4", "n5", "n6"]), "Missing authority stays unpaired")
        try require(result.originalSizes.count == 7 && result.rebuiltSizes.count == 6, "All descriptive sizes retained")
        try require(result.unassessedEvidence.contains { $0.contains("equal sizes") }, "No unchanged-code inference")
        let json = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
        try require(json.contains("assessedEvidence") && json.contains("unassessedEvidence"), "Machine-readable coverage")
    }
    static func limits() async throws {
        let budget = try RegenerationWorkBudget.start()
        do {
            try FunctionPairingProjection.validateCounts(functions: 4_097, budget: budget)
            throw Failure(message: "Oversized function list admitted")
        } catch RegenerationWorkBudgetError.recordLimitExceeded {}
        do {
            try FunctionPairingProjection.validateCounts(functions: 0, symbols: 16_385, budget: budget)
            throw Failure(message: "Oversized symbol list admitted")
        } catch RegenerationWorkBudgetError.recordLimitExceeded {}
        do {
            _ = try FunctionVersionFingerprintAdapter.capturedSymbolFingerprints(functions: [function(16)],
                symbols: [symbol(16, String(repeating: "x", count: 1_025))], budget: budget)
            throw Failure(message: "Oversized raw name admitted")
        } catch RegenerationWorkBudgetError.inputLimitExceeded {}
        do {
            let expired = try RegenerationWorkBudget(deadlineUptimeNanoseconds: 0)
            _ = try FunctionPairingProjection.compare(original: [], rebuilt: [], budget: expired)
            throw Failure(message: "Expired deadline admitted")
        } catch RegenerationWorkBudgetError.deadlineExceeded {}
        try await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try FunctionPairingProjection.compare(original: [], rebuilt: [], budget: budget)
                throw Failure(message: "Cancelled task admitted")
            } catch is CancellationError {}
        }.value
    }
}
