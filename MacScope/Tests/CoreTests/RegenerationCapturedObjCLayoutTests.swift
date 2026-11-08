import Foundation
#if !RG6_LAYOUT_STANDALONE
import XCTest
@testable import MacScope

final class RegenerationCapturedObjCLayoutTests: XCTestCase {
    func testCapturedLayoutObservationsRemainUnscoredAndBounded() throws {
        try CapturedObjCLayoutScenario.run { classes in
            var image = MachOFile(
                header: .init(magic: 0, cpuType: 0, cpuSubtype: 0, fileType: 0,
                              loadCommandCount: 0, loadCommandsSize: 0, flags: 0, reserved: 0),
                loadCommands: [], segments: [], sections: [], dylibs: [], rpaths: [], symbols: [], imports: [],
                indirectSymbols: [], relocations: [], exports: [], stringLiterals: [], objectiveCMetadata: .empty,
                swiftMetadataSections: [], exceptionMetadata: .empty, functionStarts: [], dataInCodeEntries: [],
                uuid: nil, buildVersion: nil, sourceVersion: nil, legacyMinimumOSVersion: nil,
                codeSignature: nil, dyldChainedFixups: nil, entryPointOffset: nil, entryPointVirtualAddress: nil,
                selectedSliceOffset: 0, universalBinary: nil)
            image.objectiveCMetadata.classes = classes
            return image
        }
    }
}
#endif

enum CapturedObjCLayoutScenario {
    struct Failure: Error { let message: String }
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        if !value() { throw Failure(message: message) }
    }
    static func run(makeImage: ([ObjCClass]) -> MachOFile) throws {
        func cls(_ ivars: [ObjCIvar], _ size: UInt64?) -> ObjCClass {
            .init(name: "Duplicate", superclassName: nil, adoptedProtocols: [], classMethods: [],
                  instanceMethods: [], ivars: ivars, properties: [], instanceSize: size)
        }
        let original = makeImage([
            cls([.init(name: "member", typeEncoding: "i", offset: 0, size: 4)], 16),
            cls([.init(name: "member", typeEncoding: nil, offset: nil, size: nil)], nil)
        ])
        let rebuilt = makeImage([
            cls([.init(name: "member", typeEncoding: "q", offset: 8, size: 8),
                 .init(name: "member", typeEncoding: "i", offset: 12, size: 4)], 24)
        ])
        let dimensions = try MachOStructureProjection.compare(original: original, rebuilt: rebuilt, budget: .start())
        let report = StructuralReportBuilder.build(original: "new-synthetic-original", rebuilt: "new-synthetic-rebuilt", dimensions: dimensions)
        let restored = try JSONDecoder().decode(StructuralReport.self, from: JSONEncoder().encode(report))
        let offsets = try dimension("Objective-C ivar offsets", in: restored)
        let sizes = try dimension("Objective-C ivar sizes", in: restored)
        let instances = try dimension("Objective-C instance sizes", in: restored)
        for value in [offsets, sizes, instances] {
            try require(value.comparison == nil, "Layout must not create comparison scores or differences")
            try require(value.unassessedOriginal.count == 2, "Duplicate class/ivar observations must survive")
        }
        try require(offsets.unassessedOriginal.map(\.value).contains("linkTimeByteOffset=0"), "Zero offset must survive")
        try require(offsets.unassessedOriginal.contains { $0.value == nil }, "Unknown offset must stay distinct from zero")
        try require(Set(offsets.unassessedRebuilt.compactMap(\.value)) == Set(["linkTimeByteOffset=8", "linkTimeByteOffset=12"]), "Rebuilt duplicate ivars retain both offsets")
        try require(sizes.unassessedOriginal.contains { $0.value == "staticByteCount=4" } && sizes.unassessedOriginal.contains { $0.value == nil }, "Known and unknown ivar sizes preserved")
        try require(Set(sizes.unassessedRebuilt.compactMap(\.value)) == Set(["staticByteCount=8", "staticByteCount=4"]), "Rebuilt sizes preserved")
        try require(instances.unassessedOriginal.contains { $0.value == "staticInstanceByteCount=16" } && instances.unassessedOriginal.contains { $0.value == nil }, "Known and unknown instance sizes preserved")
        try require(instances.unassessedRebuilt.map(\.value) == ["staticInstanceByteCount=24"], "Rebuilt instance size preserved")
        let markdown = StructuralReportBuilder.markdown(restored)
        for text in ["linkTimeByteOffset=0", "linkTimeByteOffset=8", "linkTimeByteOffset=12", "staticByteCount=4", "staticByteCount=8", "staticInstanceByteCount=16", "staticInstanceByteCount=24", " = unknown"] {
            try require(markdown.contains(text), "Missing Markdown observation: " + text)
        }
        // Ten existing class/type records plus eleven added layout observations = 21.
        // This cap admits the pre-change projection, but must refuse the new combined output.
        let bounded = try RegenerationWorkBudget(deadlineUptimeNanoseconds: UInt64.max, maximumRecords: 20)
        do {
            _ = try MachOStructureProjection.compare(original: original, rebuilt: rebuilt, budget: bounded)
            throw Failure(message: "New layout observations bypassed the combined record cap")
        } catch RegenerationWorkBudgetError.recordLimitExceeded {}
    }
    private static func dimension(_ name: String, in report: StructuralReport) throws -> StructuralDimensionResult {
        guard let value = report.dimensions.first(where: { $0.name == name }) else { throw Failure(message: "Missing layout dimension: " + name) }
        return value
    }
}
