import Foundation
import XCTest
@testable import MacScope

/// Synthetic source definitions; no kernelcache or KDK input.
final class MachOFilesetIndexTests: XCTestCase {
    private func put32(_ data: inout Data, _ offset: Int, _ value: UInt32) {
        for i in 0..<4 { data[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    private func put64(_ data: inout Data, _ offset: Int, _ value: UInt64) {
        for i in 0..<8 { data[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    private func header(_ data: inout Data, _ offset: Int, type: UInt32, count: UInt32, size: UInt32) {
        put32(&data, offset, 0xfeedfacf); put32(&data, offset + 4, 0x0100000c)
        put32(&data, offset + 12, type); put32(&data, offset + 16, count)
        put32(&data, offset + 20, size)
    }
    private func fixture(equalVM: Bool = false, uuid: Bool = true) -> Data {
        var data = Data(repeating: 0, count: 2048)
        header(&data, 0, type: 12, count: 2, size: 80)
        for i in 0..<2 {
            let command = 32 + i * 40, child = 512 + i * 512
            let vm = UInt64(equalVM ? 0x1000 : 0x1000 + i * 0x1000)
            put32(&data, command, 0x80000035); put32(&data, command + 4, 40)
            put64(&data, command + 8, vm); put64(&data, command + 16, UInt64(child))
            put32(&data, command + 24, 32)
            data[command + 32] = UInt8(65 + i)
            header(&data, child, type: 6, count: uuid ? 2 : 1, size: uuid ? 96 : 72)
            let segment = child + 32
            put32(&data, segment, 0x19); put32(&data, segment + 4, 72)
            for (j, byte) in Array("__TEXT".utf8).enumerated() { data[segment + 8 + j] = byte }
            put64(&data, segment + 24, vm); put64(&data, segment + 32, 128)
            put64(&data, segment + 40, UInt64(child)); put64(&data, segment + 48, 128)
            if uuid {
                put32(&data, child + 104, 0x1b); put32(&data, child + 108, 24)
                data[child + 112] = UInt8(i + 1)
            }
        }
        return data
    }
    // Synthetic caller-supplied identity labels only; these strings are not computed
    // fixture hashes, provenance evidence, or an assertion of real source admission.
    private func identity(_ data: Data, digest: String = String(repeating: "a", count: 64)) throws -> MachOSliceArtifactIdentity {
        try .init(uuid: nil, rawCPUType: MachOConstants.cpuTypeARM64, rawCPUSubtype: 0,
                  selectedSliceSHA256: digest, selectedSliceByteCount: UInt64(data.count))
    }
    private func index(_ data: Data, limits: MachOFilesetIndexLimits = .init()) throws -> MachOFilesetIndex {
        try MachOFilesetIndexParser().index(data, admittedParent: identity(data), limits: limits)
    }
    func testTwoEntriesRetainParentCoordinatesAndActualUUIDs() throws {
        let data = fixture(), result = try index(data)
        XCTAssertEqual(result.entries.map(\.identity.entryID), ["A", "B"])
        XCTAssertEqual(result.entries.map(\.identity.commandOffset), [32, 72])
        XCTAssertEqual(result.entries.map(\.identity.fileOffset), [512, 1024])
        XCTAssertEqual(result.entries.map(\.segments.first?.fileOffset), [512, 1024])
        XCTAssertNotEqual(result.entries[0].childUUID, result.entries[1].childUUID)
        XCTAssertEqual(result.parent, try identity(data))
    }
    func testEqualVirtualAddressesRemainDistinctAndExplicitlyOverlapping() throws {
        let result = try index(fixture(equalVM: true))
        XCTAssertNotEqual(result.entries[0].identity, result.entries[1].identity)
        XCTAssertTrue(result.entries.allSatisfy(\.sharesOrOverlapsAnotherEntry))
    }
    func testDifferentAdmittedParentsDoNotShareEntryIdentity() throws {
        let data = fixture()
        let a = try index(data)
        let b = try MachOFilesetIndexParser().index(data, admittedParent: identity(data, digest: String(repeating: "b", count: 64)))
        XCTAssertNotEqual(a.entries[0].identity, b.entries[0].identity)
    }
    func testMissingUUIDRemainsUnknown() throws {
        XCTAssertTrue(try index(fixture(uuid: false)).entries.allSatisfy { $0.childUUID == nil })
    }
    func testTruncatedAndDeclaredCommandEnvelopeRefuse() {
        var data = fixture(); put32(&data, 20, 72)
        XCTAssertThrowsError(try index(data))
        var truncated = fixture(); truncated.removeSubrange(60..<truncated.count)
        XCTAssertThrowsError(try index(truncated))
    }
    func testOwnCommandStringBoundsAndTerminatorRefuse() {
        var outside = fixture(); put32(&outside, 56, 40)
        XCTAssertThrowsError(try index(outside))
        var missing = fixture(); for i in 64..<72 { missing[i] = 65 }
        XCTAssertThrowsError(try index(missing))
        var headerString = fixture(); put32(&headerString, 56, 8)
        XCTAssertThrowsError(try index(headerString))
    }
    func testMisalignedCommandAndReservedEntryRefuse() {
        var data = fixture(); put32(&data, 36, 36)
        XCTAssertThrowsError(try index(data))
        data = fixture(); put32(&data, 60, 1)
        XCTAssertThrowsError(try index(data))
    }
    func testDuplicateIDAndHeaderOffsetRefuseWithoutFirstWinner() {
        var names = fixture(); names[104] = 65
        XCTAssertThrowsError(try index(names))
        var offsets = fixture(); put64(&offsets, 88, 512)
        XCTAssertThrowsError(try index(offsets))
    }
    func testChildHeaderAndSegmentFileExtentsRefuse() {
        var header = fixture(); put64(&header, 48, 2040)
        XCTAssertThrowsError(try index(header))
        var segment = fixture(); put64(&segment, 544 + 40, 2000)
        XCTAssertThrowsError(try index(segment))
    }
    func testArithmeticOverflowCannotWrapIntoContainer() {
        var file = fixture(); put64(&file, 544 + 40, UInt64.max - 8)
        XCTAssertThrowsError(try index(file))
        var virtual = fixture(); put64(&virtual, 544 + 24, UInt64.max - 8)
        XCTAssertThrowsError(try index(virtual))
        var entry = fixture(); put64(&entry, 48, UInt64.max - 7)
        XCTAssertThrowsError(try index(entry))
    }
    func testWrongArchitectureAndNestedFilesetAreExplicitUnsupported() {
        var wrong = fixture(); put32(&wrong, 512 + 4, 0x01000007)
        XCTAssertThrowsError(try index(wrong)) { error in
            guard case MachOFilesetIndexError.unsupported("architecture", _) = error else { return XCTFail("\(error)") }
        }
        var nested = fixture(); put32(&nested, 512 + 12, 12)
        XCTAssertThrowsError(try index(nested)) { error in
            guard case MachOFilesetIndexError.unsupported("nested fileset", _) = error else { return XCTFail("\(error)") }
        }
    }
    func testCompressedOrBigEndianMagicIsNotEmptySuccess() {
        for magic in [UInt32(0x706d6f63), 0xcffaedfe, 0xbebafeca] {
            var data = fixture(); put32(&data, 0, magic)
            XCTAssertThrowsError(try index(data))
        }
    }
    func testAllIndependentLimitsRefuseWithoutLargeFixture() {
        let data = fixture()
        var limits = MachOFilesetIndexLimits(); limits.maximumContainerBytes = 100
        XCTAssertThrowsError(try index(data, limits: limits))
        limits = .init(); limits.maximumCommands = 1
        XCTAssertThrowsError(try index(data, limits: limits))
        limits = .init(); limits.maximumCommandBytes = 64
        XCTAssertThrowsError(try index(data, limits: limits))
        limits = .init(); limits.maximumEntries = 1
        XCTAssertThrowsError(try index(data, limits: limits))
        limits = .init(); limits.maximumChildCommandBytes = 128
        XCTAssertThrowsError(try index(data, limits: limits))
        limits = .init(); limits.maximumSegments = 1
        XCTAssertThrowsError(try index(data, limits: limits))
        limits = .init(); limits.maximumOutputBytes = 64
        XCTAssertThrowsError(try index(data, limits: limits))
    }
    func testAbsoluteCoordinatesAreNotRebasedByChildSlicing() {
        var data = fixture(); put64(&data, 544 + 40, 0)
        XCTAssertThrowsError(try index(data)) { error in
            guard case MachOFilesetIndexError.unsupported("unproved absolute child header mapping", _) = error else { return XCTFail("\(error)") }
        }
    }
    func testIdentityLengthMismatchAndHeaderOverlapRefuse() throws {
        let data = fixture()
        let wrong = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "a", count: 64), selectedSliceByteCount: 1)
        XCTAssertThrowsError(try MachOFilesetIndexParser().index(data, admittedParent: wrong))
        var overlap = fixture(); put64(&overlap, 88, 520)
        XCTAssertThrowsError(try index(overlap))
    }
    func testStringLimitIsBoundedInsideOwnCommand() {
        var data = fixture(); data[65] = 66
        var limits = MachOFilesetIndexLimits(); limits.maximumEntryIDBytes = 1
        XCTAssertThrowsError(try index(data, limits: limits))
    }
    func testEncryptedAndProtectedMappingsRefuse() {
        var encrypted = fixture()
        put32(&encrypted, 616, 0x2c); put32(&encrypted, 632, 1)
        XCTAssertThrowsError(try index(encrypted)) { error in
            guard case MachOFilesetIndexError.unsupported("encrypted bytes", _) = error else { return XCTFail("\(error)") }
        }
        var protected = fixture(); put32(&protected, 612, 8)
        XCTAssertThrowsError(try index(protected))
    }
    func testLegalCrossEntrySharedDataIsNotGloballyRejected() throws {
        var data = fixture()
        for child in [512, 1024] {
            put32(&data, child + 16, 3); put32(&data, child + 20, 168)
            put64(&data, child + 64, 200); put64(&data, child + 80, 200)
            let segment = child + 128
            put32(&data, segment, 0x19); put32(&data, segment + 4, 72)
            put64(&data, segment + 24, 0x9000); put64(&data, segment + 32, 32)
            put64(&data, segment + 40, 1536); put64(&data, segment + 48, 32)
        }
        let result = try index(data)
        XCTAssertEqual(result.entries.count, 2)
        XCTAssertTrue(result.entries.allSatisfy(\.sharesOrOverlapsAnotherEntry))
        var limits = MachOFilesetIndexLimits(); limits.maximumMappingComparisons = 1
        XCTAssertThrowsError(try index(data, limits: limits))
    }
    func testSectionExtentAndSectionBudgetAreIndependent() throws {
        var data = fixture(uuid: false)
        put32(&data, 512 + 20, 152)
        put32(&data, 544 + 4, 152); put32(&data, 544 + 64, 1)
        put64(&data, 544 + 32, 184); put64(&data, 544 + 48, 184)
        let section = 616
        put64(&data, section + 32, 0x10b0); put64(&data, section + 40, 8)
        put32(&data, section + 48, 688)
        XCTAssertEqual(try index(data).entries.count, 2)
        put32(&data, section + 48, 2040)
        XCTAssertThrowsError(try index(data))
        put32(&data, section + 48, 688); put64(&data, section + 40, 16)
        XCTAssertThrowsError(try index(data))
        put64(&data, section + 40, 8); put32(&data, 544 + 64, 2)
        var limits = MachOFilesetIndexLimits(); limits.maximumSections = 1
        XCTAssertThrowsError(try index(data, limits: limits))
    }
    func testWellFormedTwoSectionCommandReportsSectionLimit() throws {
        var data = fixture(uuid: false)
        let child = 512, segment = 544
        put32(&data, child + 20, 232)
        put32(&data, segment + 4, 232); put32(&data, segment + 64, 2)
        put64(&data, segment + 32, 288); put64(&data, segment + 48, 288)
        // Two complete 80-byte records end at 776; their payloads follow the command.
        for (sectionIndex, name) in ["__first", "__second"].enumerated() {
            let section = segment + 72 + sectionIndex * 80
            for (offset, byte) in name.utf8.enumerated() { data[section + offset] = byte }
            for (offset, byte) in "__TEXT".utf8.enumerated() { data[section + 16 + offset] = byte }
            put64(&data, section + 32, UInt64(0x1108 + sectionIndex * 8))
            put64(&data, section + 40, 8)
            put32(&data, section + 48, UInt32(776 + sectionIndex * 8))
        }
        var limits = MachOFilesetIndexLimits(); limits.maximumSections = 2
        XCTAssertEqual(try index(data, limits: limits).entries.count, 2)
        limits.maximumSections = 1
        XCTAssertThrowsError(try index(data, limits: limits)) { error in
            guard case MachOFilesetIndexError.limit("sections") = error else {
                return XCTFail("\(error)")
            }
        }
    }

}
