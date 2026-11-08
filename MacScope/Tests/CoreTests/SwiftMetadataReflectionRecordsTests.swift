import Foundation
import XCTest
@testable import MacScope

final class SwiftMetadataReflectionRecordsTests: XCTestCase {
    // SW3 / item 1249: authored crafted-byte regressions.
    func testSW3UnresolvedSubstitutionPreservesRecordAndFallbackWithSlotDiagnostic() throws {
        var image = ImageBuilder()
        let conforming = image.relSlot(), proto = image.relSlot()
        image.u32(2); image.u32(8)
        let name1 = image.relSlot(), type1 = image.relSlot()
        let name2 = image.relSlot(), type2 = image.relSlot()
        let length = image.count
        image.patchString(conforming, "Si"); image.patchString(proto, "SS")
        image.patchString(name1, "Element"); image.patchString(name2, "Index")
        // Complete symbolic indirect reference, with no bind/rebase evidence: unresolved.
        let symbolic = image.mangledBytes([0x02, 0, 0, 0, 0])
        image.patchRel(type1, symbolic)
        image.patchString(type2, "Si")
        let report = image.parser(section: "__swift5_assocty", length: length).parseAssociatedTypesReport()
        XCTAssertEqual(report.records.count, 1)
        let record = try XCTUnwrap(report.records.first)
        XCTAssertEqual(record.descriptorAddress, 0)
        XCTAssertEqual(record.conformingTypeName, "Int")
        XCTAssertEqual(record.protocolTypeName, "String")
        XCTAssertEqual(record.associatedTypes.map(\.name), ["Element", "Index"])
        XCTAssertEqual(record.associatedTypes.map(\.substitutedTypeName), ["…", "Int"])
        XCTAssertEqual(report.diagnostics.count, 1)
        let diagnostic = try XCTUnwrap(report.diagnostics.first)
        XCTAssertEqual(diagnostic.code, .unresolvedGenericReference)
        XCTAssertEqual(diagnostic.grade, .skippedItem)
        XCTAssertEqual(diagnostic.address, UInt64(type1))
        XCTAssertEqual(diagnostic.message, "Unresolved associated-type substitution mangling: needsFixup")
        // The string is retained evidence, not a fabricated resolved semantic identity.
        let restored = try JSONDecoder().decode(SwiftAssociatedTypeRecord.self,
                                               from: JSONEncoder().encode(record))
        XCTAssertEqual(restored, record)
    }

    func testSW3SyntheticUnresolvedSubstitutionDiagnosticsAreBoundedWithoutDroppingRecords() throws {
        // Synthetic budget control only; this is not an app/oracle count reproduction.
        let budget = MetadataParseDiagnosticLog.maxEntries
        let count = budget + 1
        var image = ImageBuilder()
        let conforming = image.relSlot(), proto = image.relSlot()
        image.u32(UInt32(count)); image.u32(8)
        var names: [Int] = [], types: [Int] = []
        for _ in 0..<count {
            names.append(image.relSlot()); types.append(image.relSlot())
        }
        let length = image.count
        image.patchString(conforming, "Si"); image.patchString(proto, "SS")
        let name = image.cstring("Element")
        let symbolic = image.mangledBytes([0x02, 0, 0, 0, 0])
        for index in 0..<count {
            image.patchRel(names[index], name); image.patchRel(types[index], symbolic)
        }
        let report = image.parser(section: "__swift5_assocty", length: length).parseAssociatedTypesReport()
        XCTAssertEqual(report.records.count, 1)
        let record = try XCTUnwrap(report.records.first)
        XCTAssertEqual(record.descriptorAddress, 0)
        XCTAssertEqual(record.associatedTypes.count, count)
        XCTAssertEqual(record.associatedTypes.map(\.name), Array(repeating: "Element", count: count))
        XCTAssertEqual(record.associatedTypes.map(\.substitutedTypeName), Array(repeating: "…", count: count))
        let details = report.diagnostics.filter { $0.grade == .skippedItem }
        XCTAssertEqual(details.count, budget)
        XCTAssertEqual(details.map(\.address), types.prefix(budget).map { UInt64($0) })
        XCTAssertTrue(details.allSatisfy { $0.code == .unresolvedGenericReference })
        let summaries = report.diagnostics.filter { $0.grade == .walkCapped }
        XCTAssertEqual(summaries.count, 1)
        let summary = try XCTUnwrap(summaries.first)
        XCTAssertEqual(summary.code, .unresolvedGenericReference)
        XCTAssertEqual(summary.address, UInt64(types[budget]))
        XCTAssertEqual(summary.message, "Omitted 1 additional unresolved associated-type substitution diagnostics")
        XCTAssertEqual(report.diagnostics.count, budget + 1)
    }

    func testCapturePreservesMetadataSourcePairsAndBindings() {
        var image = ImageBuilder()
        image.u32(1); image.u32(1); image.u32(2)
        let capture = image.relSlot(), sourceType = image.relSlot(), source = image.relSlot()
        let length = image.count
        image.patchString(capture, "Si")
        image.patchString(sourceType, "SS")
        image.patchString(source, "B0")
        let report = image.parser(section: "__swift5_capture", length: length).parseCaptureDescriptorsReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.records.count, 1)
        XCTAssertEqual(report.records.first?.captureTypeNames, ["Int"])
        XCTAssertEqual(report.records.first?.metadataSources.first?.typeName, "String")
        XCTAssertEqual(report.records.first?.metadataSources.first?.sourceName, "B0")
        XCTAssertEqual(report.records.first?.numBindings, 2)
    }

    func testTruncatedCaptureProducesDiagnostic() {
        var image = ImageBuilder()
        image.u32(1); image.u32(0); image.u32(0)
        let report = image.parser(section: "__swift5_capture").parseCaptureDescriptorsReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
    }

    func testAssociatedTypesHonorEmittedRecordStride() {
        var image = ImageBuilder()
        let conforming = image.relSlot(), proto = image.relSlot()
        image.u32(2); image.u32(12)
        let name1 = image.relSlot(), type1 = image.relSlot(); image.u32(0xdeadbeef)
        let name2 = image.relSlot(), type2 = image.relSlot(); image.u32(0xdeadbeef)
        let length = image.count
        image.patchString(conforming, "4Demo1SV")
        image.patchString(proto, "4Demo1PP")
        image.patchString(name1, "A"); image.patchString(type1, "Si")
        image.patchString(name2, "B"); image.patchString(type2, "SS")
        let report = image.parser(section: "__swift5_assocty", length: length).parseAssociatedTypesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.records.count, 1)
        XCTAssertEqual(report.records.first?.associatedTypes.map(\.name), ["A", "B"])
        XCTAssertEqual(report.records.first?.associatedTypes.map(\.substitutedTypeName), ["Int", "String"])
    }

    func testTruncatedAssociatedTypeProducesDiagnostic() {
        var image = ImageBuilder()
        image.u32(1); image.u32(1); image.u32(1); image.u32(8)
        let report = image.parser(section: "__swift5_assocty").parseAssociatedTypesReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
    }

    func testAssociatedTypeStrideBelowMinimumProducesDiagnostic() {
        var image = ImageBuilder()
        image.u32(1); image.u32(1); image.u32(1); image.u32(4); image.u32(0)
        let report = image.parser(section: "__swift5_assocty").parseAssociatedTypesReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
    }

    func testBuiltinTypePreservesLayoutAndFlags() {
        var image = ImageBuilder()
        let type = image.relSlot()
        image.u32(7); image.u32(0x10008); image.u32(8); image.u32(3)
        let length = image.count
        image.patchString(type, "Si")
        let report = image.parser(section: "__swift5_builtin", length: length).parseBuiltinTypesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.records.first?.typeName, "Int")
        XCTAssertEqual(report.records.first?.size, 7)
        XCTAssertEqual(report.records.first?.alignmentAndFlags, 0x10008)
        XCTAssertEqual(report.records.first?.stride, 8)
        XCTAssertEqual(report.records.first?.extraInhabitantCount, 3)
    }

    func testTruncatedBuiltinTypeProducesDiagnostic() {
        var image = ImageBuilder()
        image.u32(1); image.u32(8); image.u32(8); image.u32(8)
        let report = image.parser(section: "__swift5_builtin").parseBuiltinTypesReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
    }

    func testMultiPayloadEnumReadsMaskCountAndSkipsMaskPadding() {
        var image = ImageBuilder()
        let type = image.relSlot()
        image.u32(0x30001); image.u32(0x20003); image.u32(0x00ffffff)
        let secondType = image.relSlot(); image.u32(0x10000)
        let length = image.count
        image.patchString(type, "4Demo1EO")
        image.patchString(secondType, "4Demo1FO")
        let report = image.parser(section: "__swift5_mpenum", length: length).parseMultiPayloadEnumsReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.records.map(\.maskByteCount), [3, 0])
    }

    func testTruncatedMultiPayloadEnumProducesDiagnostic() {
        var image = ImageBuilder()
        image.u32(1); image.u32(0x30001); image.u32(3)
        let report = image.parser(section: "__swift5_mpenum").parseMultiPayloadEnumsReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
    }

    func testMultiPayloadEnumRejectsMaskLargerThanRecord() {
        var image = ImageBuilder()
        image.u32(1); image.u32(0x20001); image.u32(9)
        let report = image.parser(section: "__swift5_mpenum").parseMultiPayloadEnumsReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
    }
}

private extension ImageBuilder {
    mutating func patchString(_ slot: Int, _ value: String) {
        let target = cstring(value)
        patchRel(slot, target)
    }
    func parser(section: String, length: Int? = nil) -> SwiftMetadataParser {
        let length = length ?? count
        var sections: [SwiftMetadataParser.Section] = [
            .init(name: section, address: 0, fileOffset: 0, size: UInt64(length))
        ]
        if count > length {
            sections.append(.init(name: "__swift5_typeref", address: UInt64(length),
                                  fileOffset: UInt64(length), size: UInt64(count - length)))
        }
        return SwiftMetadataParser(data: Data(data), sections: sections)
    }
}
