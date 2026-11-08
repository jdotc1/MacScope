import Foundation
import Testing
@testable import MacScope

struct SwiftErrorFlowNativeAdapterTests {
    // Catches replacing raw nlist flags/name/ordinal with a display or guessed symbol.
    @Test func preservesRawNListEvidence() throws {
        let parsed = try SwiftErrorFlowMachOReader.parse(fixture())
        #expect(parsed.symbols.count == 1)
        #expect(parsed.symbols.first?.name == "_$s4Test3fooyyKF")
        #expect(parsed.symbols.first?.nType == 0x0f)
        #expect(parsed.symbols.first?.nDesc == 0x0080)
        #expect(parsed.symbols.first?.sectionOrdinal == 1)
        #expect(parsed.words == Array(repeating: 0xd65f03c0, count: 8))
    }

    // Catches inferring a last end from the section end, alignment or a RET.
    @Test func omitsFinalStartWithoutDeclaredFollowingBoundary() throws {
        let parsed = try SwiftErrorFlowMachOReader.parse(fixture())
        #expect(parsed.functions.count == 2)
        #expect(parsed.functions[0].start == 0x1100)
        #expect(parsed.functions[0].endExclusive == 0x1110)
        #expect(parsed.functions[1].start == 0x1110)
        #expect(parsed.functions[1].endExclusive == 0x1118)
        #expect(!parsed.functions.contains { $0.start == 0x1118 })
    }

    // Catches treating a retained prefix or nonzero trailing padding as complete.
    @Test func rejectsUnterminatedFunctionStarts() {
        var bytes = fixture()
        bytes[0x184] = 1
        #expect(throws: SwiftErrorFlowAdapterError.self) { try SwiftErrorFlowMachOReader.parse(bytes) }
    }

    @Test func rejectsFunctionStartsTrailingNonzeroBytes() {
        var bytes = fixture()
        write32(6, at: 196, to: &bytes)
        bytes[0x185] = 1
        #expect(throws: SwiftErrorFlowAdapterError.self) { try SwiftErrorFlowMachOReader.parse(bytes) }
    }

    // Catches accepting a relocation count merely because projected relocations are empty.
    @Test func rejectsRawTextRelocations() {
        var bytes = fixture()
        write32(1, at: 164, to: &bytes)
        #expect(throws: SwiftErrorFlowAdapterError.self) { try SwiftErrorFlowMachOReader.parse(bytes) }
    }

    @Test func rejectsArm64eAndSubtypeCapabilities() {
        for subtype in [UInt32(2), UInt32(0x80000000)] {
            var bytes = fixture()
            write32(subtype, at: 8, to: &bytes)
            #expect(throws: SwiftErrorFlowAdapterError.self) { try SwiftErrorFlowMachOReader.parse(bytes) }
        }
    }

    @Test func rejectsUnmappedSectionCoordinates() {
        var bytes = fixture()
        write32(0x104, at: 152, to: &bytes)
        #expect(throws: SwiftErrorFlowAdapterError.self) { try SwiftErrorFlowMachOReader.parse(bytes) }
    }

    @Test func rejectsOutOfBoundsSymbolTable() {
        var bytes = fixture()
        write32(0x3ff, at: 208, to: &bytes)
        #expect(throws: SwiftErrorFlowAdapterError.self) { try SwiftErrorFlowMachOReader.parse(bytes) }
    }

    // Catches a sectionless segment supplying a second VM/file mapping for code.
    @Test func rejectsAliasingSegmentWithoutSections() {
        var bytes = fixture()
        write32(4, at: 16, to: &bytes)
        write32(264, at: 20, to: &bytes)
        write64(0x1140, at: 136, to: &bytes)
        write32(0x140, at: 152, to: &bytes)
        bytes.replaceSubrange(224..<296, with: repeatElement(UInt8(0), count: 72))
        write32(0x19, at: 224, to: &bytes)
        write32(72, at: 228, to: &bytes)
        writeString("__ALIAS", at: 232, to: &bytes)
        write64(0x1000, at: 248, to: &bytes)
        write64(0x400, at: 256, to: &bytes)
        write64(0, at: 264, to: &bytes)
        write64(0x400, at: 272, to: &bytes)
        write32(5, at: 280, to: &bytes)
        write32(5, at: 284, to: &bytes)
        for offset in stride(from: 0x140, to: 0x160, by: 4) { write32(0xd65f03c0, at: offset, to: &bytes) }
        bytes[0x180] = 0xc0
        write64(0x1140, at: 0x208, to: &bytes)
        #expect(throws: SwiftErrorFlowAdapterError("ambiguous_text_mapping")) {
            try SwiftErrorFlowMachOReader.parse(bytes)
        }
    }

    private func fixture() -> Data {
        var bytes = Data(repeating: 0, count: 0x400)
        write32(0xfeedfacf, at: 0, to: &bytes)
        write32(0x0100000c, at: 4, to: &bytes)
        write32(0, at: 8, to: &bytes)
        write32(2, at: 12, to: &bytes)
        write32(3, at: 16, to: &bytes)
        write32(192, at: 20, to: &bytes)
        write32(0x19, at: 32, to: &bytes)
        write32(152, at: 36, to: &bytes)
        writeString("__TEXT", at: 40, to: &bytes)
        write64(0x1000, at: 56, to: &bytes)
        write64(0x400, at: 64, to: &bytes)
        write64(0, at: 72, to: &bytes)
        write64(0x400, at: 80, to: &bytes)
        write32(5, at: 88, to: &bytes)
        write32(5, at: 92, to: &bytes)
        write32(1, at: 96, to: &bytes)
        writeString("__text", at: 104, to: &bytes)
        writeString("__TEXT", at: 120, to: &bytes)
        write64(0x1100, at: 136, to: &bytes)
        write64(32, at: 144, to: &bytes)
        write32(0x100, at: 152, to: &bytes)
        write32(2, at: 156, to: &bytes)
        write32(0x80000400, at: 168, to: &bytes)
        write32(0x26, at: 184, to: &bytes)
        write32(16, at: 188, to: &bytes)
        write32(0x180, at: 192, to: &bytes)
        write32(5, at: 196, to: &bytes)
        write32(2, at: 200, to: &bytes)
        write32(24, at: 204, to: &bytes)
        write32(0x200, at: 208, to: &bytes)
        write32(1, at: 212, to: &bytes)
        write32(0x210, at: 216, to: &bytes)
        write32(64, at: 220, to: &bytes)
        for offset in stride(from: 0x100, to: 0x120, by: 4) { write32(0xd65f03c0, at: offset, to: &bytes) }
        bytes.replaceSubrange(0x180..<0x185, with: [0x80, 0x02, 0x10, 0x08, 0])
        write32(1, at: 0x200, to: &bytes)
        bytes[0x204] = 0x0f
        bytes[0x205] = 1
        bytes[0x206] = 0x80
        write64(0x1100, at: 0x208, to: &bytes)
        writeString("_$s4Test3fooyyKF", at: 0x211, to: &bytes)
        return bytes
    }

    private func write32(_ value: UInt32, at offset: Int, to bytes: inout Data) {
        for i in 0..<4 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (i * 8)) }
    }

    private func write64(_ value: UInt64, at offset: Int, to bytes: inout Data) {
        for i in 0..<8 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (i * 8)) }
    }

    private func writeString(_ value: String, at offset: Int, to bytes: inout Data) {
        bytes.replaceSubrange(offset..<(offset + value.utf8.count), with: value.utf8)
    }
}
