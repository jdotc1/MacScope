import Foundation
import XCTest
@testable import MacScope

/// Synthetic in-memory bytes only; no real kernel input.
final class MachOFilesetChildInspectionTests: XCTestCase {
    private func put32(_ bytes: inout Data, _ at: Int, _ value: UInt32) {
        for shift in 0..<4 { bytes[at + shift] = UInt8(truncatingIfNeeded: value >> (shift * 8)) }
    }
    private func put64(_ bytes: inout Data, _ at: Int, _ value: UInt64) {
        for shift in 0..<8 { bytes[at + shift] = UInt8(truncatingIfNeeded: value >> (shift * 8)) }
    }
    private func name(_ bytes: inout Data, _ at: Int, _ value: String) {
        for (position, byte) in value.utf8.enumerated() { bytes[at + position] = byte }
    }
    private func header(_ bytes: inout Data, _ at: Int, _ kind: UInt32, _ count: UInt32, _ size: UInt32) {
        put32(&bytes, at, 0xfeedfacf); put32(&bytes, at + 4, 0x0100000c)
        put32(&bytes, at + 12, kind); put32(&bytes, at + 16, count); put32(&bytes, at + 20, size)
    }
    private func entry(_ bytes: inout Data, _ at: Int, _ child: UInt64, _ vm: UInt64, _ id: String) {
        put32(&bytes, at, 0x80000035); put32(&bytes, at + 4, 40)
        put64(&bytes, at + 8, vm); put64(&bytes, at + 16, child)
        put32(&bytes, at + 24, 32); name(&bytes, at + 32, id)
    }
    private func fixture(neighbor: Bool = false, uuid: Bool = true) -> Data {
        var bytes = Data(repeating: 0, count: 4_096)
        header(&bytes, 0, 12, neighbor ? 2 : 1, neighbor ? 80 : 40)
        entry(&bytes, 32, 512, 0x1000, "first")
        header(&bytes, 512, 6, uuid ? 3 : 2, uuid ? 264 : 240)
        put32(&bytes, 544, 0x19); put32(&bytes, 548, 232); name(&bytes, 552, "__DATA")
        put64(&bytes, 568, 0x1000); put64(&bytes, 576, 0x800)
        put64(&bytes, 584, 512); put64(&bytes, 592, 0x700); put32(&bytes, 608, 2)
        name(&bytes, 616, "__data"); name(&bytes, 632, "__DATA")
        put64(&bytes, 648, 0x1600); put64(&bytes, 656, 16); put32(&bytes, 664, 2_048)
        put32(&bytes, 668, 3)
        name(&bytes, 696, "__bss"); name(&bytes, 712, "__DATA")
        put64(&bytes, 728, 0x1780); put64(&bytes, 736, 32)
        put32(&bytes, 748, 4); put32(&bytes, 760, 1)
        if uuid {
            put32(&bytes, 776, 0x1b); put32(&bytes, 780, 24); bytes[784] = 0x11
        }
        let unknown = uuid ? 800 : 776
        put32(&bytes, unknown, 0x7777); put32(&bytes, unknown + 4, 8)
        bytes[2_048] = 0xa5; bytes[2_560] = 0x5a
        if neighbor {
            entry(&bytes, 72, 1_024, 0x4000, "next")
            header(&bytes, 1_024, 6, 1, 72)
            put32(&bytes, 1_056, 0x19); put32(&bytes, 1_060, 72); name(&bytes, 1_064, "__TEXT")
            put64(&bytes, 1_080, 0x4000); put64(&bytes, 1_088, 128)
            put64(&bytes, 1_096, 1_024); put64(&bytes, 1_104, 128)
        }
        return bytes
    }
    private func parent(_ bytes: Data, uuid: UUID? = nil) throws -> MachOSliceArtifactIdentity {
        try .init(uuid: uuid, rawCPUType: MachOConstants.cpuTypeARM64, rawCPUSubtype: 0,
                  selectedSliceSHA256: String(repeating: "a", count: 64), selectedSliceByteCount: UInt64(bytes.count))
    }
    private func selector(_ parent: MachOSliceArtifactIdentity) -> MachOFilesetIndex.Identity {
        .init(parent: parent, commandOffset: 32, fileOffset: 512, virtualAddress: 0x1000, entryID: "first")
    }
    private func inspect(_ bytes: Data, limits: MachOFilesetChildInspectionLimits = .init()) throws -> MachOFilesetChildInspection {
        let identity = try parent(bytes)
        return try MachOParser().inspectFilesetChild(in: bytes, admittedParent: identity,
                                                    selecting: selector(identity), limits: limits)
    }
    func testWholeParentCoordinatesAreNotSuffixCoordinates() throws {
        let bytes = fixture(), result = try inspect(bytes)
        let first = try XCTUnwrap(result.sections.first)
        XCTAssertEqual(first.parentFileOffset, 2_048)
        XCTAssertEqual(first.fileByteCount, 16)
        XCTAssertEqual(bytes[Int(try XCTUnwrap(first.parentFileOffset))], 0xa5)
        XCTAssertEqual(bytes[512 + Int(try XCTUnwrap(first.parentFileOffset))], 0x5a)
        XCTAssertEqual(result.identity, selector(try parent(bytes)))
        XCTAssertEqual(result.commands[0].parentFileOffset, 544)
        XCTAssertEqual(result.commands[0].offsetFromChildHeader, 32)
        let suffix = Data(bytes.dropFirst(512)), identity = try parent(bytes)
        XCTAssertThrowsError(try MachOParser().inspectFilesetChild(in: suffix, admittedParent: identity,
                                                                  selecting: selector(identity)))
    }
    func testUsefulSectionMetadataZeroFillAndOptionalUUID() throws {
        let result = try inspect(fixture())
        XCTAssertEqual(result.sections.map(\.sectionName), ["__data", "__bss"])
        XCTAssertEqual(result.sections[0].segmentName, "__DATA")
        XCTAssertEqual(result.sections[0].virtualAddress, 0x1600)
        XCTAssertEqual(result.sections[0].alignmentExponent, 3)
        XCTAssertEqual(result.sections[1].virtualSize, 32)
        XCTAssertTrue(result.sections[1].isZeroFill)
        XCTAssertNil(result.sections[1].parentFileOffset)
        XCTAssertNil(result.sections[1].fileByteCount)
        XCTAssertEqual(result.sections[1].rawFileOffset, 0)
        XCTAssertNotNil(result.childUUID)
        XCTAssertNil(try inspect(fixture(uuid: false)).childUUID)
    }
    func testUnknownCommandsAndSemanticPayloadsRemainUninspected() throws {
        let result = try inspect(fixture())
        XCTAssertEqual(result.commands.map(\.coverage), [.segmentAndSections, .uuid, .envelopeOnly])
        XCTAssertEqual(result.commands.last?.command, 0x7777)
        XCTAssertTrue(result.semanticCoverage.contains("uninspected"))
        XCTAssertTrue(result.semanticCoverage.contains("relocations"))
        XCTAssertTrue(result.semanticCoverage.contains("fixups"))
    }
    func testNeighborHeaderIsNotTheSelectedChildExtent() throws {
        let result = try inspect(fixture(neighbor: true))
        XCTAssertEqual(result.sections[0].parentFileOffset, 2_048) // Later than neighbor header at1024.
        XCTAssertEqual(result.segments[0].fileOffset, 512)
        XCTAssertEqual(result.segments[0].fileSize, 0x700)
        XCTAssertTrue(result.sharesOrOverlapsAnotherEntry)
    }
    func testAllSelectorCoordinatesAndParentMustAgree() throws {
        let bytes = fixture(), identity = try parent(bytes)
        let selectors: [MachOFilesetIndex.Identity] = [
            .init(parent: identity, commandOffset: 40, fileOffset: 512, virtualAddress: 0x1000, entryID: "first"),
            .init(parent: identity, commandOffset: 32, fileOffset: 520, virtualAddress: 0x1000, entryID: "first"),
            .init(parent: identity, commandOffset: 32, fileOffset: 512, virtualAddress: 0x1008, entryID: "first"),
            .init(parent: identity, commandOffset: 32, fileOffset: 512, virtualAddress: 0x1000, entryID: "missing")
        ]
        for selected in selectors {
            XCTAssertThrowsError(try MachOParser().inspectFilesetChild(in: bytes, admittedParent: identity, selecting: selected))
        }
        let other = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "b", count: 64), selectedSliceByteCount: UInt64(bytes.count))
        XCTAssertThrowsError(try MachOParser().inspectFilesetChild(in: bytes, admittedParent: other, selecting: selector(identity)))
    }
    func testDuplicateEntryIdentityNeverSelectsFirst() {
        var bytes = fixture(neighbor: true)
        for i in 104..<112 { bytes[i] = 0 }; name(&bytes, 104, "first")
        XCTAssertThrowsError(try inspect(bytes))
    }
    func testCommandAlignmentCountAndEnvelopeRefuse() {
        for (offset, value) in [(548, UInt32(228)), (528, 4), (532, 256), (804, 16)] {
            var bytes = fixture(); put32(&bytes, offset, value)
            XCTAssertThrowsError(try inspect(bytes))
        }
    }
    func testSectionVMFileAndSegmentOverflowRefuse() {
        for offset in [648, 656, 568, 576, 584, 592] {
            var bytes = fixture(); put64(&bytes, offset, UInt64.max - 3)
            XCTAssertThrowsError(try inspect(bytes))
        }
        var outside = fixture(); put32(&outside, 664, 3_000)
        XCTAssertThrowsError(try inspect(outside))
    }
    func testSectionInteriorSpansMustFitTheirDeclaringSegment() {
        var bytes = fixture(); put32(&bytes, 664, 2_300) // Inside segment, but16 bytes cross its end2304.
        XCTAssertThrowsError(try inspect(bytes))
        bytes = fixture(); put64(&bytes, 648, 0x17f8)
        XCTAssertThrowsError(try inspect(bytes))
    }
    func testSectionOverlapIsNotUniqueOwnership() {
        var bytes = fixture(); put64(&bytes, 728, 0x1608)
        XCTAssertThrowsError(try inspect(bytes))
        bytes = fixture(); put32(&bytes, 760, 0); put32(&bytes, 744, 2_052)
        XCTAssertThrowsError(try inspect(bytes))
    }
    func testNameMismatchInvalidUTF8AndControlNamesRefuse() {
        var bytes = fixture(); bytes[632] = 65
        XCTAssertThrowsError(try inspect(bytes))
        bytes = fixture(); bytes[616] = 0xff
        XCTAssertThrowsError(try inspect(bytes))
        bytes = fixture(); bytes[616] = 10
        XCTAssertThrowsError(try inspect(bytes))
    }
    func testRelocationDescriptorIsRetainedWithoutPayloadInterpretation() throws {
        var bytes = fixture(); put32(&bytes, 672, 3_000); put32(&bytes, 676, 1)
        let result = try inspect(bytes)
        XCTAssertEqual(result.sections[0].relocationOffset, 3_000)
        XCTAssertEqual(result.sections[0].relocationCount, 1)
        XCTAssertTrue(result.semanticCoverage.contains("relocations")) // Outside child segment, never read.
    }
    func testUUIDMultiplicityAndParentMismatchRefuse() throws {
        var bytes = fixture(); put32(&bytes, 800, 0x1b)
        XCTAssertThrowsError(try inspect(bytes))
        // Add actual outer UUID after its entry, without changing child positions.
        bytes = fixture(); put32(&bytes, 16, 2); put32(&bytes, 20, 64)
        put32(&bytes, 72, 0x1b); put32(&bytes, 76, 24); bytes[80] = 1
        let wrong = try parent(bytes, uuid: UUID(uuidString: "02000000-0000-0000-0000-000000000000")!)
        XCTAssertThrowsError(try MachOParser().inspectFilesetChild(in: bytes, admittedParent: wrong, selecting: selector(wrong)))
    }
    func testIndependentDetailBudgetsRefuseBeforeResultPublication() {
        let bytes = fixture()
        var limits = MachOFilesetChildInspectionLimits(); limits.maximumInputBytes = 100
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.maximumCommands = 2
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.maximumCommandBytes = 240
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.maximumSections = 1
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.maximumNameBytes = 79
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.maximumOutputBytes = 4_096
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.maximumSections = 0
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        limits = .init(); limits.indexLimits.maximumEntries = 1
        XCTAssertThrowsError(try inspect(fixture(neighbor: true), limits: limits))
    }
    func testEscapedNamesRemainBoundedAndExact() throws {
        var bytes = fixture(); for i in 616..<632 { bytes[i] = 0 }
        name(&bytes, 616, "\"\\field")
        let result = try inspect(bytes)
        XCTAssertEqual(result.sections[0].sectionName, "\"\\field")
        var limits = MachOFilesetChildInspectionLimits(); limits.maximumOutputBytes = 5_000
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
    }
    func testNonzeroDataIndexOriginStillMeansWholeParentCoordinates() throws {
        let original = fixture()
        var padded = Data(repeating: 0, count: 16); padded.append(original)
        let retained = padded.dropFirst(16)
        XCTAssertEqual(try inspect(retained).sections[0].parentFileOffset, 2_048)
    }
    func testComparisonBudgetAndAlignmentRefuse() {
        var bytes = fixture()
        for i in 776..<888 { bytes[i] = 0 }
        put32(&bytes, 532, 344); put32(&bytes, 548, 312); put32(&bytes, 608, 3)
        name(&bytes, 776, "__tail"); name(&bytes, 792, "__DATA")
        put64(&bytes, 808, 0x17c0); put64(&bytes, 816, 8); put32(&bytes, 840, 1)
        put32(&bytes, 856, 0x1b); put32(&bytes, 860, 24); bytes[864] = 0x11
        put32(&bytes, 880, 0x7777); put32(&bytes, 884, 8)
        var limits = MachOFilesetChildInspectionLimits(); limits.maximumSectionComparisons = 1
        XCTAssertThrowsError(try inspect(bytes, limits: limits))
        bytes = fixture(); put32(&bytes, 668, 64)
        XCTAssertThrowsError(try inspect(bytes))
    }
    func testWithinChildSegmentOverlapRemainsRefused() {
        var bytes = fixture()
        put32(&bytes, 532, 328)
        put32(&bytes, 800, 0x19); put32(&bytes, 804, 72)
        put64(&bytes, 824, 0x1500); put64(&bytes, 832, 64)
        put64(&bytes, 840, 1_800); put64(&bytes, 848, 64)
        XCTAssertThrowsError(try inspect(bytes))
    }
}
