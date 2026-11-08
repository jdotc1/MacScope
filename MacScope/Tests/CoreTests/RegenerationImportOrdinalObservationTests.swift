import Foundation
#if !RG6_IMPORT_ORDINAL_STANDALONE
import XCTest
@testable import MacScope

final class RegenerationImportOrdinalObservationTests: XCTestCase {
    func testReportedOrdinalsRemainDistinctUnscoredAndBounded() throws {
        try ImportOrdinalObservationScenario.run { imports in
            MachOFile(
                header: .init(magic: 0, cpuType: 0, cpuSubtype: 0, fileType: 0,
                    loadCommandCount: 0, loadCommandsSize: 0, flags: 0, reserved: 0),
                loadCommands: [], segments: [], sections: [], dylibs: [], rpaths: [],
                symbols: [], imports: imports, indirectSymbols: [], relocations: [], exports: [],
                stringLiterals: [], objectiveCMetadata: .empty, swiftMetadataSections: [],
                exceptionMetadata: .empty, functionStarts: [], dataInCodeEntries: [],
                uuid: nil, buildVersion: nil, sourceVersion: nil, legacyMinimumOSVersion: nil,
                codeSignature: nil, dyldChainedFixups: nil, entryPointOffset: nil,
                entryPointVirtualAddress: nil, selectedSliceOffset: 0, universalBinary: nil)
        }
    }
}
#endif

enum ImportOrdinalObservationScenario {
    struct Failure: Error { let message: String }
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        if !value() { throw Failure(message: message) }
    }
    static func run(makeImage: ([MachOImport]) -> MachOFile) throws {
        func imports(_ ordinals: [Int?]) -> [MachOImport] {
            ordinals.enumerated().map { index, ordinal in
                .init(symbolIndex: index, name: "_same", libraryOrdinal: ordinal, libraryName: nil)
            }
        }
        let original = makeImage(imports([7, 8, nil, 0]))
        let rebuilt = makeImage(imports([9, nil]))
        let dimensions = try MachOStructureProjection.compare(original: original, rebuilt: rebuilt, budget: .start())
        let report = StructuralReportBuilder.build(original: "synthetic-original", rebuilt: "synthetic-rebuilt", dimensions: dimensions)
        let restored = try JSONDecoder().decode(StructuralReport.self, from: JSONEncoder().encode(report))
        guard let observations = restored.dimensions.first(where: { $0.name == "imports" }) else {
            throw Failure(message: "Missing import observations")
        }
        try require(observations.comparison == nil, "Ordinals must not create cross-image scores or differences")
        try require(observations.unassessedOriginal.count == 4 && observations.unassessedRebuilt.count == 2,
            "Same-name observations must remain separate")
        func detail(_ ordinal: String) -> String {
            "reportedLibraryOrdinal=\(ordinal);weak=false;addend=unknown;source=import table"
        }
        try require(Set(observations.unassessedOriginal.compactMap(\.value)) ==
            Set(["7", "8", "unknown", "0"].map(detail)), "Reported ordinal values, including nil versus zero")
        try require(Set(observations.unassessedRebuilt.compactMap(\.value)) ==
            Set(["9", "unknown"].map(detail)), "Rebuilt reported values")
        try require(Set(observations.unassessedOriginal.map(\.key)).count == 1,
            "Ordinal must remain observation detail, not cross-image identity")
        let markdown = StructuralReportBuilder.markdown(restored)
        for ordinal in ["7", "8", "9", "unknown", "0"] {
            try require(markdown.contains("reportedLibraryOrdinal=\(ordinal);"), "Missing rendered ordinal")
        }
        let bounded = try RegenerationWorkBudget(deadlineUptimeNanoseconds: UInt64.max, maximumRecords: 5)
        do {
            _ = try MachOStructureProjection.compare(original: original, rebuilt: rebuilt, budget: bounded)
            throw Failure(message: "Combined import observation cap bypassed")
        } catch RegenerationWorkBudgetError.recordLimitExceeded {}
    }
}

