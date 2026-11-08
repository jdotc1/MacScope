import Foundation
import XCTest
@testable import MacScope

// T2 guard; F3; complete ordered FunctionSummary equality includes stable IDs,
// names, bounds, confidence and provenance (Hashable). Authored, unrun.
final class DiscoveryPreparationEqualityTests: XCTestCase {
    func testGuardThresholdsForcedProceduresDataAndUnavailable() {
        for count in [4095, 4096, 4097, 8192] {
            var rows = ReadyFixture.instructions(count: count)
            rows[2].mnemonic = "unavailable"
            var loaded = ReadyFixture.binary(instructions: rows)
            loaded.symbols = [
                SymbolSummary(id: UUID(), name: "first", address: 0x1010, kind: "local", libraryName: nil),
                SymbolSummary(id: UUID(), name: "second", address: 0x1010, kind: "local", libraryName: nil),
                SymbolSummary(id: UUID(), name: "outside", address: 0x1001, kind: "local", libraryName: nil)
            ]
            let engine = AnalysisEngine()
            let prepared = DiscoveryPreparationStore()
            let uncached = DiscoveryPreparationStore(entryLimit: 0)
            let forced: Set<UInt64> = [0x1004, 0x1008, 0x100c, 0x1001]
            let data: Set<UInt64> = [0x100c]
            let expected = engine.functionSummariesForTesting(from: loaded,
                codeSection: loaded.executableTextSection, decodedInstructions: rows,
                dataAddresses: data, procedureAddresses: forced, preparation: uncached)
            let actual = engine.functionSummariesForTesting(from: loaded,
                codeSection: loaded.executableTextSection, decodedInstructions: rows,
                dataAddresses: data, procedureAddresses: forced, preparation: prepared)
            XCTAssertEqual(actual, expected)
            XCTAssertEqual(actual.map(\.startAddress), [0x1000, 0x1004, 0x1010])
            XCTAssertEqual(actual.map(\.id), actual.map {
                AnalysisStableIdentity.functionID(slot: .primary, startAddress: $0.startAddress)
            })
        }
    }
    func testGuardDuplicateAddressesDirectCallsAndIndependentSections() {
        let store = DiscoveryPreparationStore()
        for section in 0..<2 {
            var rows = ReadyFixture.instructions(count: 6)
            for index in rows.indices { rows[index].address += UInt64(section * 0x100) }
            rows[0].flow = .call; rows[0].branchTarget = rows[0].address
            rows[1].flow = .call; rows[1].branchTarget = rows[4].address
            rows[2].flow = .call; rows[2].branchTarget = rows[5].address + 4
            rows[3].flow = .call; rows[3].branchTarget = rows[0].address - 1
            rows.append(rows[4])
            let start = rows[0].address
            let result = store.prepare(sectionOrdinal: section, instructions: rows,
                codeStart: start, codeEnd: start + 24, existingStarts: [start])
            XCTAssertEqual(result?.decodedAddresses.count, 6)
            XCTAssertEqual(result?.baselineDirectCalls, [start + 16])
            var loaded = ReadyFixture.binary(instructions: rows)
            let codeSection = BinarySection(name: ".text", address: start, size: 24,
                fileOffset: start - 0x1000, isExecutable: true)
            loaded.sections = [codeSection]
            loaded.executableTextSection = codeSection
            loaded.functionStarts = [start]
            loaded.entryPointAddress = start
            let engine = AnalysisEngine()
            let actual = engine.functionSummariesForTesting(from: loaded, codeSection: codeSection,
                decodedInstructions: rows, preparation: store, sectionOrdinal: section)
            let expected = engine.functionSummariesForTesting(from: loaded, codeSection: codeSection,
                decodedInstructions: rows, preparation: DiscoveryPreparationStore(entryLimit: 0), sectionOrdinal: section)
            XCTAssertEqual(actual, expected)
            XCTAssertEqual(actual.map(\.startAddress), [start, start + 16])
            XCTAssertEqual(actual.map(\.id), actual.map {
                AnalysisStableIdentity.functionID(slot: .primary, startAddress: $0.startAddress)
            })
        }
        XCTAssertEqual(store.statistics.admissions, 2)
    }
    func testGuardZeroSizeRejectsEveryStart() {
        let rows = ReadyFixture.instructions(count: 4)
        var loaded = ReadyFixture.binary(instructions: rows)
        var section = loaded.executableTextSection!
        section.size = 0
        loaded.executableTextSection = section
        for budget in [0, 12] {
            let functions = AnalysisEngine().functionSummariesForTesting(from: loaded,
                codeSection: section, decodedInstructions: rows,
                preparation: DiscoveryPreparationStore(entryLimit: budget))
            XCTAssertEqual(functions, [])
        }
    }
}
