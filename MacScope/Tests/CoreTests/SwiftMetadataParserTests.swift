import Foundation
import XCTest
@testable import MacScope

final class SwiftMetadataParserTests: XCTestCase {

    // MARK: - Hermetic fixture (always runs, no toolchain)

    /// A hand-laid Swift reflection image with identity VA==fileOffset, so a relative pointer's
    /// stored value is simply `targetOffset - fieldOffset`. Exercises the full chain:
    /// __swift5_types → type context descriptor → __swift5_fieldmd → records, including a resolved
    /// standard-library type (`Si`→Int), a null mangled type (→ nil), and the IsVar flag.
    func testHermeticStructWithFields() {
        var b = ImageBuilder()
        let fnFirst = b.cstring("first")
        let fnSecond = b.cstring("second")
        let mtFirst = b.cstring("Si")
        let nameOff = b.cstring("Pair")
        b.align(4)

        let fd = b.count
        b.u32(0); b.u32(0)        // MangledTypeName, Superclass (unused here)
        b.u16(0); b.u16(12)       // Kind = struct, FieldRecordSize = 12
        b.u32(2)                  // NumFields
        b.u32(0); let r0mt = b.relSlot(); let r0fn = b.relSlot()   // record 0: let first: Int
        b.u32(2); _ = b.relSlot(); let r1fn = b.relSlot()          // record 1: var second (no type)

        b.align(4)
        let td = b.count
        b.u32(17); b.u32(0)       // Flags = struct kind, Parent = null
        let tdName = b.relSlot(); b.u32(0); let tdFields = b.relSlot()
        b.u32(2); b.u32(0)        // NumFields, FieldOffsetVectorOffset

        b.align(4)
        let tyv = b.count
        let tyEntry = b.relSlot()

        b.patchRel(r0mt, mtFirst)
        b.patchRel(r0fn, fnFirst)
        b.patchRel(r1fn, fnSecond)   // r1's mangled-type slot left 0 (null) → typeName nil
        b.patchRel(tdName, nameOff)
        b.patchRel(tdFields, fd)
        b.patchRel(tyEntry, td)

        let sections = [
            SwiftMetadataParser.Section(name: "__swift5_types", address: UInt64(tyv), fileOffset: UInt64(tyv), size: 4),
            SwiftMetadataParser.Section(name: "__const", address: 0, fileOffset: 0, size: UInt64(tyv)),
        ]
        let types = SwiftMetadataParser(data: Data(b.data), sections: sections).parseTypes()

        XCTAssertEqual(types.count, 1)
        let pair = try? XCTUnwrap(types.first)
        XCTAssertEqual(pair?.kind, .struct)
        XCTAssertEqual(pair?.name, "Pair")
        XCTAssertEqual(pair?.fields.count, 2)
        XCTAssertEqual(pair?.fields[0], SwiftField(name: "first", typeName: "Int", mangledTypeName: "Si", isVar: false))
        XCTAssertEqual(pair?.fields[1], SwiftField(name: "second", typeName: nil, mangledTypeName: nil, isVar: true))

        let rendered = SwiftInterfaceRenderer.render(types: types)
        XCTAssertEqual(rendered, "struct Pair {\n    let first: Int\n    var second\n}")
    }

    func testFieldRecordFlagsSeparateIndirectCaseFromVar() {
        var b = ImageBuilder()
        let indirectName = b.cstring("indirectCase")
        let mutableName = b.cstring("mutableCase")
        let typeName = b.cstring("Flags")
        b.align(4)

        let fields = b.count
        b.u32(0); b.u32(0)
        b.u16(2); b.u16(12) // Kind = enum, FieldRecordSize = 12
        b.u32(2)
        b.u32(0x1); _ = b.relSlot(); let indirectFieldName = b.relSlot()
        b.u32(0x2); _ = b.relSlot(); let mutableFieldName = b.relSlot()

        b.align(4)
        let descriptor = b.count
        b.u32(18); b.u32(0) // enum context kind, null parent
        let descriptorName = b.relSlot(); b.u32(0); let descriptorFields = b.relSlot()
        b.u32(2); b.u32(0)

        b.align(4)
        let typeList = b.count
        let typeEntry = b.relSlot()

        b.patchRel(indirectFieldName, indirectName)
        b.patchRel(mutableFieldName, mutableName)
        b.patchRel(descriptorName, typeName)
        b.patchRel(descriptorFields, fields)
        b.patchRel(typeEntry, descriptor)

        let parsed = SwiftMetadataParser(data: Data(b.data), sections: [
            .init(name: "__swift5_types", address: UInt64(typeList), fileOffset: UInt64(typeList), size: 4),
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(typeList)),
        ]).parseTypes().first?.fields ?? []

        XCTAssertEqual(parsed.map(\.isIndirectCase), [true, false])
        XCTAssertEqual(parsed.map(\.isVar), [false, true])
    }

    func testStaticFieldOffsetsRequireCompleteNonGenericMetadata() {
        func recover(flags: UInt32, truncate: Bool = false, rebase: Bool = false) -> [SwiftField] {
            var b = ImageBuilder()
            let typeName = b.cstring("Pair")
            let first = b.cstring("first"), second = b.cstring("second")
            b.align(4)
            let fields = b.count
            b.u32(0); b.u32(0); b.u16(0); b.u16(12); b.u32(2)
            b.u32(0); b.u32(0); let f0 = b.relSlot()
            b.u32(0); b.u32(0); let f1 = b.relSlot()
            let descriptor = b.count
            b.u32(flags); b.u32(0); let name = b.relSlot(); b.u32(0); let fd = b.relSlot()
            b.u32(2); b.u32(2)
            let types = b.count, typeSlot = b.relSlot()
            b.align(8)
            let metadata = b.count
            b.u32(0x200); b.u32(0)
            b.u32(rebase ? 0xdead : UInt32(descriptor)); b.u32(0)
            b.u32(0)
            if !truncate { b.u32(24) } // descriptor value, deliberately unlike an inferred ABI layout
            b.patchRel(f0, first); b.patchRel(f1, second)
            b.patchRel(name, typeName); b.patchRel(fd, fields); b.patchRel(typeSlot, descriptor)
            return SwiftMetadataParser(data: Data(b.data), sections: [
                .init(name: "__swift5_types", address: UInt64(types), fileOffset: UInt64(types), size: 4),
                .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(types)),
                .init(name: "__const", address: UInt64(types + 4), fileOffset: UInt64(types + 4), size: UInt64(b.count - (types + 4))),
            ], rebaseTargets: rebase ? [UInt64(metadata + 8): UInt64(descriptor)] : [:],
               metadataAddresses: rebase ? [] : [UInt64(metadata)]).parseTypes().first?.fields ?? []
        }
        XCTAssertEqual(recover(flags: 17).map(\.byteOffset), [0, 24])
        XCTAssertEqual(recover(flags: 17, rebase: true).map(\.byteOffset), [0, 24])
        XCTAssertEqual(recover(flags: 17, truncate: true).map(\.byteOffset), [nil, nil])
        XCTAssertEqual(recover(flags: 17 | 0x80).map(\.byteOffset), [nil, nil])
        XCTAssertEqual(recover(flags: 17 | (1 << 16)).map(\.byteOffset), [nil, nil])
    }

    func testSymbolMetadataOutranksUnrelatedRebaseCandidateRegardlessOfAddressOrder() {
        // M is genuine metadata. R is an unrelated record whose shape happens to match it.
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[0, 24], [128, 256]],
                                              symbols: [0], rebases: [1]), [0, 24])
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[128, 256], [0, 24]],
                                              symbols: [1], rebases: [0]), [0, 24])
    }

    func testConflictingSymbolMetadataRemainsUnknownInsteadOfUsingHeuristicFallback() {
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[0, 24], [128, 256], [8, 16]],
                                              symbols: [0, 1], rebases: [2]), [nil, nil])
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[0, 24], [128, 256], [8, 16]],
                                              symbols: [1, 0], rebases: [2]), [nil, nil])
    }

    func testConflictingHeuristicMetadataRemainsUnknownEvenWithMatchingVectors() {
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[0, 24], [128, 256]],
                                              symbols: [], rebases: [0, 1]), [nil, nil])
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[0, 24], [0, 24]],
                                              symbols: [], rebases: [0, 1]), [nil, nil])
    }

    func testDuplicateSymbolAliasesAtOneAddressAreNotAmbiguous() {
        XCTAssertEqual(recoverCandidateOffsets(vectors: [[0, 24], [128, 256]],
                                              symbols: [0, 0], rebases: [0, 1]), [0, 24])
    }

    private func recoverCandidateOffsets(vectors: [[UInt32]], symbols: [Int], rebases: [Int]) -> [UInt64?] {
        var b = ImageBuilder()
        let typeName = b.cstring("Pair"), first = b.cstring("first"), second = b.cstring("second")
        b.align(4)
        let fields = b.count
        b.u32(0); b.u32(0); b.u16(0); b.u16(12); b.u32(2)
        b.u32(0); b.u32(0); let f0 = b.relSlot()
        b.u32(0); b.u32(0); let f1 = b.relSlot()
        let descriptor = b.count
        b.u32(17); b.u32(0); let name = b.relSlot(); b.u32(0); let fd = b.relSlot()
        b.u32(2); b.u32(2) // NumFields = 2, FieldOffsetVectorOffset = 2 words
        let types = b.count, typeSlot = b.relSlot()
        b.align(8)
        var addresses: [UInt64] = []
        for vector in vectors {
            addresses.append(UInt64(b.count))
            b.u32(0x200); b.u32(0)
            b.u32(UInt32(descriptor)); b.u32(0)
            b.u32(vector[0]); b.u32(vector[1])
        }
        b.patchRel(f0, first); b.patchRel(f1, second)
        b.patchRel(name, typeName); b.patchRel(fd, fields); b.patchRel(typeSlot, descriptor)
        return SwiftMetadataParser(data: Data(b.data), sections: [
            .init(name: "__swift5_types", address: UInt64(types), fileOffset: UInt64(types), size: 4),
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(types)),
            .init(name: "__const", address: UInt64(types + 4), fileOffset: UInt64(types + 4), size: UInt64(b.count - (types + 4))),
        ], rebaseTargets: Dictionary(uniqueKeysWithValues: rebases.map { (addresses[$0] + 8, UInt64(descriptor)) }),
           metadataAddresses: symbols.map { addresses[$0] }).parseTypes().first?.fields.map(\.byteOffset) ?? []
    }

    // MARK: - SW1 static offset controls (AUTHORED, UNRUN, NOT CONFIRMED)

    // All expected offsets below are literal image words, never calculated from field types.
    // No Mints/TG Pro binary or compiled-layout receipt was supplied. No test run was made.
    private struct SW1OffsetFixture {
        var bytes: [UInt8]
        var sections: [SwiftMetadataParser.Section]
        var descriptor: UInt64
        var fieldDescriptor: UInt64
        var metadata: UInt64
        var vector: UInt64
        var decoy: UInt64 = 0
    }

    private func sw1StructFixture(flags: UInt32 = 17, nominalCount: UInt32 = 2,
                                  recordCount: Int = 2, skippedRecord: Int? = nil,
                                  vectorValues: [UInt32] = [0, 40]) -> SW1OffsetFixture {
        var b = ImageBuilder()
        let name = b.cstring("SW1Fixture")
        let fieldNames = (0..<recordCount).map { b.cstring("field\($0)") }
        b.align(4)
        let fields = b.count
        b.u32(0); b.u32(0); b.u16(0); b.u16(12); b.u32(UInt32(recordCount))
        for record in 0..<recordCount {
            b.u32(0); b.u32(0); let slot = b.relSlot()
            if skippedRecord != record { b.patchRel(slot, fieldNames[record]) }
        }
        let descriptor = b.count
        b.u32(flags); b.u32(0)
        let nameSlot = b.relSlot(); b.u32(0); let fieldsSlot = b.relSlot()
        b.u32(nominalCount); b.u32(2) // +20 count, +24 vector offset in eight-byte words
        let types = b.count, entry = b.relSlot()
        b.align(8)
        let metadata = b.count
        b.u32(0x200); b.u32(0); b.u32(UInt32(descriptor)); b.u32(0)
        let vector = b.count
        for value in vectorValues { b.u32(value) } // four-byte entries, exact source of offsets
        b.patchRel(nameSlot, name); b.patchRel(fieldsSlot, fields); b.patchRel(entry, descriptor)
        return .init(bytes: b.data, sections: [
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(types)),
            .init(name: "__swift5_types", address: UInt64(types), fileOffset: UInt64(types), size: 4),
            .init(name: "__metadata", address: UInt64(metadata), fileOffset: UInt64(metadata), size: 16),
            .init(name: "__offsets", address: UInt64(vector), fileOffset: UInt64(vector), size: UInt64(vectorValues.count * 4)),
        ], descriptor: UInt64(descriptor), fieldDescriptor: UInt64(fields),
           metadata: UInt64(metadata), vector: UInt64(vector))
    }

    private func sw1Types(_ fixture: SW1OffsetFixture, metadataPresent: Bool = true,
                          rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:]) -> [SwiftTypeDescriptor] {
        SwiftMetadataParser(data: Data(fixture.bytes), sections: fixture.sections,
                            rebaseTargets: rebases, bindNames: binds,
                            metadataAddresses: metadataPresent ? [fixture.metadata] : []).parseTypes()
    }

    private func sw1Offsets(_ fixture: SW1OffsetFixture, metadataPresent: Bool = true,
                            rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:]) -> [UInt64?] {
        sw1Types(fixture, metadataPresent: metadataPresent, rebases: rebases, binds: binds)
            .first?.fields.map(\.byteOffset) ?? []
    }

    func testSW1CompleteStructVectorUsesLiteralWords_NOT_CONFIRMED() {
        let fixture = sw1StructFixture()
        XCTAssertEqual(sw1Offsets(fixture), [0, 40])
        // Zero does not prove an unfilled vector; zero-sized fields may share an offset.
        XCTAssertEqual(sw1Offsets(sw1StructFixture(vectorValues: [0, 0])), [0, 0])
        // Existing descriptor-pointer rebase discovery is retained, not read as an offset.
        XCTAssertEqual(sw1Offsets(fixture, metadataPresent: false,
                                  rebases: [fixture.metadata + 8: fixture.descriptor]), [0, 40])
    }

    func testSW1MissingOrUnreadableVectorIsEntirelyUnknown_NOT_CONFIRMED() {
        let fixture = sw1StructFixture()
        XCTAssertEqual(sw1Offsets(fixture, metadataPresent: false), [nil, nil])

        var noVectorWord = fixture
        for byte in 0..<4 { noVectorWord.bytes[Int(fixture.descriptor) + 24 + byte] = 0 }
        XCTAssertEqual(sw1Offsets(noVectorWord), [nil, nil])

        var absent = fixture
        absent.sections.removeLast() // bytes exist but the vector has no section footprint
        XCTAssertEqual(sw1Offsets(absent), [nil, nil])

        var truncated = fixture
        truncated.bytes.removeLast() // declared eight-byte vector has only seven file bytes
        XCTAssertEqual(sw1Offsets(truncated), [nil, nil])

        var short = sw1StructFixture(vectorValues: [0]) // raw/nominal field counts remain two
        XCTAssertEqual(sw1Offsets(short), [nil, nil])

        var zeroFill = fixture
        zeroFill.sections[3].isZeroFill = true
        XCTAssertEqual(sw1Offsets(zeroFill), [nil, nil])

        var overlap = fixture
        overlap.sections.append(.init(name: "__alias", address: fixture.vector + 7,
                                      fileOffset: fixture.vector + 7, size: 1))
        XCTAssertEqual(sw1Offsets(overlap), [nil, nil])
        overlap.sections[4].isZeroFill = true // even a partial zero-fill competitor is ambiguous
        XCTAssertEqual(sw1Offsets(overlap), [nil, nil])

        short = fixture
        short.sections[3].size = 4
        short.sections.append(.init(name: "__second_half", address: fixture.vector + 4,
                                    fileOffset: fixture.vector + 4, size: 4))
        XCTAssertEqual(sw1Offsets(short), [nil, nil]) // no single complete vector footprint
    }

    func testSW1PointerFixupOverlapCannotBecomeScalarOffsets_NOT_CONFIRMED() {
        let fixture = sw1StructFixture()
        // Include a pointer beginning seven bytes before the vector and one at its last byte.
        for delta in [-7, -4, 0, 3, 7] {
            let slot = UInt64(Int64(fixture.vector) + Int64(delta))
            XCTAssertEqual(sw1Offsets(fixture, rebases: [slot: 0xdead]), [nil, nil])
            XCTAssertEqual(sw1Offsets(fixture, binds: [slot: "_external"]), [nil, nil])
        }
        // Half-open boundaries: the descriptor pointer ends where the vector starts.
        XCTAssertEqual(sw1Offsets(fixture, rebases: [fixture.vector - 8: fixture.descriptor]), [0, 40])
        XCTAssertEqual(sw1Offsets(fixture, binds: [fixture.vector + 8: "_outside"]), [0, 40])
        XCTAssertEqual(sw1Offsets(fixture, rebases: [fixture.descriptor + 20: 0xdead]), [nil, nil])
        XCTAssertEqual(sw1Offsets(fixture, binds: [fixture.fieldDescriptor + 12: "_count"]), [nil, nil])
    }

    func testSW1SkippedRawOrdinalCannotShiftOntoSurvivingFields_NOT_CONFIRMED() {
        // Raw records: [unreadable name, field1, field2]. Nominal/vector count is two.
        // The pin compared only the two survivors and assigned vector[0] to raw record 1.
        let fixture = sw1StructFixture(recordCount: 3, skippedRecord: 0)
        let fields = sw1Types(fixture).first?.fields ?? []
        XCTAssertEqual(fields.map(\.name), ["field1", "field2"])
        XCTAssertEqual(fields.map(\.byteOffset), [nil, nil])
        XCTAssertEqual(sw1Offsets(sw1StructFixture(nominalCount: 1)), [nil, nil])
        XCTAssertEqual(sw1Offsets(sw1StructFixture(recordCount: 3)), [nil, nil, nil])
    }

    func testSW1GenericIncompleteAndEnumRemainUnknown_NOT_CONFIRMED() {
        let cases: [UInt32] = [17 | 0x80, 17 | (1 << 16), 17 | (2 << 16), 17 | (3 << 16), 18]
        for flags in cases {
            XCTAssertEqual(sw1Offsets(sw1StructFixture(flags: flags)), [nil, nil])
        }
    }

    func testSW1OffsetDoesNotChangeRenderingOrOldPayloadCompatibility_NOT_CONFIRMED() throws {
        let fixture = sw1StructFixture()
        let recorded = sw1Types(fixture), unknown = sw1Types(fixture, metadataPresent: false)
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: recorded), SwiftInterfaceRenderer.render(types: unknown))
        let old = try JSONDecoder().decode(SwiftField.self, from: Data(#"{"name":"old","isVar":false}"#.utf8))
        XCTAssertNil(old.byteOffset)
        let encoded = try JSONEncoder().encode(old)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertNil(object["byteOffset"])
        let known = SwiftField(name: "known", byteOffset: 40)
        XCTAssertEqual(try JSONDecoder().decode(SwiftField.self, from: JSONEncoder().encode(known)).byteOffset, 40)
    }

    // MARK: - SW1C class vectors

    /// A class descriptor with metadata laid out as the 64-bit ObjC-platform TargetClassMetadata:
    /// 64-byte header (InstanceSize u32@48, Data@32), descriptor@64, IVarDestroyer@72, vector at word `words`.
    private func sw1ClassFixture(flags: UInt32 = 16, nominalCount: UInt32 = 2, words: UInt32 = 10,
                                 vector: [UInt64] = [16, 40], instanceSize: UInt32 = 48,
                                 superclass: String? = nil, roFlags: UInt32? = nil,
                                 decoy: Bool = false) -> SW1OffsetFixture {
        var b = ImageBuilder()
        let name = b.cstring("SW1Class"), first = b.cstring("first"), second = b.cstring("second")
        let superName = superclass.map { b.cstring($0) }
        b.align(4)
        let fields = b.count
        b.u32(0); b.u32(0); b.u16(1); b.u16(12); b.u32(2)
        b.u32(0); b.u32(0); let f0 = b.relSlot()
        b.u32(0); b.u32(0); let f1 = b.relSlot()
        let descriptor = b.count
        b.u32(flags); b.u32(0); let n = b.relSlot(); b.u32(0); let fd = b.relSlot()
        let superSlot = b.relSlot()                 // +20 SuperclassType (0 = root class)
        b.u32(1); b.u32(12); b.u32(2)               // +24 negative, +28 positive, +32 immediate members
        b.u32(nominalCount); b.u32(words)           // +36 NumFields, +40 FieldOffsetVectorOffset (words)
        let types = b.count, entry = b.relSlot()
        b.align(8)
        let ro = b.count
        if let roFlags { b.u32(roFlags); b.u32(0); b.u32(0); b.u32(0) }
        b.align(8)
        func emitMetadata() -> Int {
            let start = b.count
            for _ in 0..<16 { b.u32(0) }
            b.data.replaceSubrange((start + 48)..<(start + 52), with: (0..<4).map { UInt8((instanceSize >> (8 * UInt32($0))) & 0xff) })
            if roFlags != nil {
                let pointer = UInt64(ro) | 1
                b.data.replaceSubrange((start + 32)..<(start + 40), with: (0..<8).map { UInt8((pointer >> (8 * UInt64($0))) & 0xff) })
            }
            b.u32(UInt32(descriptor)); b.u32(0)     // descriptor pointer@+64
            b.u32(0); b.u32(0)                      // ivar-destroyer@+72
            while b.count < start + Int(words) * 8 { b.u32(0) }
            for value in vector { b.u64(value) }
            return start
        }
        let metadata = emitMetadata()
        var decoyMetadata = 0
        if decoy { b.align(8); decoyMetadata = emitMetadata() }
        let end = b.count
        b.patchRel(f0, first); b.patchRel(f1, second)
        b.patchRel(n, name); b.patchRel(fd, fields); b.patchRel(entry, descriptor)
        if let superName { b.patchRel(superSlot, superName) }
        return SW1OffsetFixture(bytes: b.data, sections: [
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(types)),
            .init(name: "__swift5_types", address: UInt64(types), fileOffset: UInt64(types), size: 4),
            .init(name: "__metadata", address: UInt64(types + 4), fileOffset: UInt64(types + 4), size: UInt64(end - types - 4)),
        ], descriptor: UInt64(descriptor), fieldDescriptor: UInt64(fields),
           metadata: UInt64(metadata), vector: UInt64(metadata + Int(words) * 8), decoy: UInt64(decoyMetadata))
    }

    private func sw1ClassParser(_ fixture: SW1OffsetFixture, symbols: [UInt64]? = nil, objc: [UInt64] = [],
                                provisional: Bool = false, rebases: [UInt64: UInt64] = [:]) -> SwiftMetadataParser {
        SwiftMetadataParser(data: Data(fixture.bytes), sections: fixture.sections, rebaseTargets: rebases,
                            metadataAddresses: symbols ?? [fixture.metadata], objcClassAddresses: objc,
                            allowProvisionalObjCRootedClassOffsets: provisional)
    }

    private func sw1ClassOffsets(_ fixture: SW1OffsetFixture, symbols: [UInt64]? = nil, objc: [UInt64] = [],
                                 provisional: Bool = false, rebases: [UInt64: UInt64] = [:]) -> [UInt64?] {
        sw1ClassParser(fixture, symbols: symbols, objc: objc, provisional: provisional, rebases: rebases)
            .parseTypes().first?.fields.map(\.byteOffset) ?? []
    }

    func testSW1ProposedCompleteClassVector_NOT_VERIFIED_NOT_CONFIRMED() {
        // Metadata.h:1119 StoredPointer entries at metadata + FieldOffsetVectorOffset words (descriptor +36/+40).
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture()), [16, 40])
        // R2 alone (stripped image, no `N` symbol): the ObjC class list names the metadata.
        let fixture = sw1ClassFixture()
        XCTAssertEqual(sw1ClassOffsets(fixture, symbols: [], objc: [fixture.metadata]), [16, 40])
        XCTAssertEqual(sw1ClassOffsets(fixture, symbols: [fixture.metadata], objc: [fixture.metadata]), [16, 40])
        // No metadata evidence at all: unknown.
        XCTAssertEqual(sw1ClassOffsets(fixture, symbols: []), [nil, nil])
        // Equal non-decreasing offsets are legal (zero-sized fields share an offset).
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [16, 16])), [16, 16])
    }

    func testSW1ClassVectorGatesEachLeaveTheWholeClassUnknown() {
        let unknown: [UInt64?] = [nil, nil]
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [16, 0])), unknown, "zero is a runtime placeholder")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [0, 0])), unknown)
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [40, 16])), unknown, "decreasing entry")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [16, 56], instanceSize: 48)), unknown, "past InstanceSize")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [8, 16])), unknown, "before the root-class header")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(flags: 16 | (1 << 29))), unknown, "resilient superclass bit")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(flags: 16 | (1 << 16))), unknown, "singleton initialization")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(flags: 16 | (2 << 16))), unknown, "foreign initialization")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(flags: 16 | 0x80)), unknown, "generic")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(nominalCount: 3)), unknown, "NumFields mismatch")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(words: 0)), unknown, "no vector")
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(words: 9)), unknown, "vector inside the header")
        // Update/FixedOrUpdate: class_ro_t flag bit 6 set means the runtime may rewrite offsets.
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(roFlags: 1 << 6)), unknown)
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(roFlags: 0x80)), [16, 40])
    }

    func testSW1ClassVectorFixupOverlapCannotBecomeOffsets() {
        let fixture = sw1ClassFixture()
        for slot in [fixture.vector, fixture.vector + 8, fixture.vector - 7, fixture.vector + 15] {
            XCTAssertEqual(sw1ClassOffsets(fixture, rebases: [slot: 0x1234]), [nil, nil], "fixup at \(slot - fixture.vector)")
        }
        let beforeVector = fixture.vector - 8
        XCTAssertEqual(sw1ClassOffsets(fixture, rebases: [beforeVector: 0x1234]), [16, 40])
    }

    func testSW1ClassMetadataSourcesThatDisagreeLeaveClassUnknown() {
        let fixture = sw1ClassFixture(decoy: true)
        XCTAssertNotEqual(fixture.decoy, 0)
        // R1 and R2 name different metadata for one descriptor: unknown, not either side.
        XCTAssertEqual(sw1ClassOffsets(fixture, symbols: [fixture.metadata], objc: [fixture.decoy]), [nil, nil])
        // Two symbols for one descriptor are ambiguous even though the vectors agree.
        XCTAssertEqual(sw1ClassOffsets(fixture, symbols: [fixture.metadata, fixture.decoy]), [nil, nil])
        XCTAssertEqual(sw1ClassOffsets(fixture, symbols: [fixture.metadata], objc: [fixture.metadata]), [16, 40])
    }

    func testSW1ClassAncestryV1() {
        // Root: starts after the header. NSObject: only for a caller that will cross-check, start 8.
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [8, 16], superclass: "So8NSObjectC")), [nil, nil])
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [8, 16], superclass: "So8NSObjectC"), provisional: true), [8, 16])
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(vector: [4, 16], superclass: "So8NSObjectC"), provisional: true), [nil, nil])
        // Other ObjC superclasses and any Swift superclass stay unknown (Q8 A).
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(superclass: "So6NSViewC"), provisional: true), [nil, nil])
        XCTAssertEqual(sw1ClassOffsets(sw1ClassFixture(superclass: "4main1AC"), provisional: true), [nil, nil])
    }

    private func sw1CrossCheck(_ fixture: SW1OffsetFixture, ivars: [UInt64?]?, instanceSize: UInt64? = 48,
                               superclass: String? = nil, objcAddress: UInt64? = nil) -> [UInt64?] {
        let parser = sw1ClassParser(fixture, objc: [fixture.metadata], provisional: true)
        let types = parser.parseTypes()
        let classes = ivars.map { values in
            [ObjCClass(name: "SW1Class", superclassName: nil, adoptedProtocols: [], classMethods: [],
                       instanceMethods: [],
                       ivars: values.enumerated().map { ObjCIvar(name: "i\($0.offset)", typeEncoding: nil,
                                                                 offset: $0.element, size: 8) },
                       properties: [], address: objcAddress ?? fixture.metadata, instanceSize: instanceSize)]
        } ?? []
        return MachOParser.crossCheckedClassOffsets(types, parser: parser, objcClasses: classes)
            .first?.fields.map(\.byteOffset) ?? []
    }

    func testSW1IvarCrossCheckAgreesDisagreesAndAbsent() {
        let root = sw1ClassFixture()
        XCTAssertEqual(sw1CrossCheck(root, ivars: [16, 40]), [16, 40], "ivar offsets agree")
        XCTAssertEqual(sw1CrossCheck(root, ivars: [16, 32]), [nil, nil], "ivar disagreement clears the class")
        XCTAssertEqual(sw1CrossCheck(root, ivars: [16]), [nil, nil], "ivar count disagreement")
        XCTAssertEqual(sw1CrossCheck(root, ivars: [16, nil]), [nil, nil], "unresolved ivar offset")
        XCTAssertEqual(sw1CrossCheck(root, ivars: [16, 40], instanceSize: 44), [nil, nil], "past class_ro instanceSize")
        XCTAssertEqual(sw1CrossCheck(root, ivars: nil), [16, 40], "root class without an ObjC entry keeps its vector")
        XCTAssertEqual(sw1CrossCheck(root, ivars: [16, 32], objcAddress: root.metadata + 8), [16, 40],
                       "an ObjC entry at another address is not this class")
        let rooted = sw1ClassFixture(vector: [8, 16], superclass: "So8NSObjectC")
        XCTAssertEqual(sw1CrossCheck(rooted, ivars: [8, 16]), [8, 16])
        XCTAssertEqual(sw1CrossCheck(rooted, ivars: [8, 24]), [nil, nil])
        XCTAssertEqual(sw1CrossCheck(rooted, ivars: nil), [nil, nil], "NSObject-rooted needs the ObjC confirmation")
    }

    // MARK: - Qualified names (context-parent walk)

    /// Appends a context descriptor `Flags Parent Name Access Fields` plus padding; parent/name are
    /// direct relative pointers (parent 0 = null). Returns its offset.
    private func contextDescriptor(_ b: inout ImageBuilder, flags: UInt32, parent: Int?, nameAt: Int) -> Int {
        b.align(4)
        let at = b.count
        b.u32(flags)
        let parentSlot = b.relSlot(), nameSlot = b.relSlot()
        b.u32(0); b.u32(0); b.u32(0); b.u32(0)
        if let parent { b.patchRel(parentSlot, parent) }
        b.patchRel(nameSlot, nameAt)
        return at
    }

    private func parseTypes(_ b: inout ImageBuilder, entries: [Int]) -> [SwiftTypeDescriptor] {
        b.align(4)
        let list = b.count
        for entry in entries { let slot = b.relSlot(); b.patchRel(slot, entry) }
        return SwiftMetadataParser(data: Data(b.data), sections: [
            .init(name: "__swift5_types", address: UInt64(list), fileOffset: UInt64(list), size: UInt64(entries.count * 4)),
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(list)),
        ]).parseTypes()
    }

    func testNestedTypeGetsModuleQualifiedNameBesideSimpleName() {
        var b = ImageBuilder()
        let mod = b.cstring("Mod"), outerName = b.cstring("Outer"), innerName = b.cstring("Inner")
        let module = contextDescriptor(&b, flags: 0, parent: nil, nameAt: mod)
        let outer = contextDescriptor(&b, flags: 17, parent: module, nameAt: outerName)
        let inner = contextDescriptor(&b, flags: 17, parent: outer, nameAt: innerName)
        let types = parseTypes(&b, entries: [inner, outer])
        XCTAssertEqual(types.map(\.name), ["Inner", "Outer"])
        XCTAssertEqual(types.map(\.qualifiedName), ["Mod.Outer.Inner", "Mod.Outer"])
        XCTAssertEqual(types.map(\.descriptorAddress), [UInt64(inner), UInt64(outer)])
    }

    func testTypeInExtensionTakesTheExtendedTypesPathAndAnonymousContextsAreTransparent() {
        var b = ImageBuilder()
        let mod = b.cstring("Mod"), outerName = b.cstring("Outer"), nestedName = b.cstring("Nested")
        let privateName = b.cstring("Hidden"), arrayExtName = b.cstring("Sa"), oddExtName = b.cstring("Sq9weird")
        let module = contextDescriptor(&b, flags: 0, parent: nil, nameAt: mod)
        let outer = contextDescriptor(&b, flags: 17, parent: module, nameAt: outerName)
        // Extension of the local `Outer`: the extended type is a symbolic reference (0x01 + rel32).
        let extMangled = b.count
        b.byte(0x01); let extRef = b.relSlot(); b.byte(0)
        b.patchRel(extRef, outer)
        let ext = contextDescriptor(&b, flags: 1, parent: module, nameAt: extMangled)
        let nested = contextDescriptor(&b, flags: 17, parent: ext, nameAt: nestedName)
        // Extension of a stdlib type, and one this reader cannot name.
        let arrayExt = contextDescriptor(&b, flags: 1, parent: module, nameAt: arrayExtName)
        let inArray = contextDescriptor(&b, flags: 17, parent: arrayExt, nameAt: nestedName)
        let oddExt = contextDescriptor(&b, flags: 1, parent: module, nameAt: oddExtName)
        let inOdd = contextDescriptor(&b, flags: 17, parent: oddExt, nameAt: nestedName)
        // A private-discriminator anonymous context between the type and its module is transparent.
        let anonymous = contextDescriptor(&b, flags: 2, parent: module, nameAt: privateName)
        let hidden = contextDescriptor(&b, flags: 17, parent: anonymous, nameAt: privateName)
        let types = parseTypes(&b, entries: [nested, inArray, inOdd, hidden])
        XCTAssertEqual(types.map(\.name), ["Nested", "Nested", "Nested", "Hidden"])
        XCTAssertEqual(types.map(\.qualifiedName), ["Mod.Outer.Nested", "Swift.Array.Nested",
                                                     "Mod.<ext:Sq9weird>.Nested", "Mod.Hidden"])
    }

    func testUnterminatedExtensionNamesLeaveQualifiedNameNil() {
        // End of data, cap exhaustion (even with a later NUL), and a truncated symbolic payload.
        let names: [[UInt8]] = [Array("Sa".utf8), Array(repeating: 0x61, count: 4_096) + [0], [0x01, 0xff]]
        for bytes in names {
            var b = ImageBuilder()
            let mod = b.cstring("Mod"), name = b.cstring("Nested")
            let module = contextDescriptor(&b, flags: 0, parent: nil, nameAt: mod)
            let ext = contextDescriptor(&b, flags: 1, parent: module, nameAt: mod)
            let nested = contextDescriptor(&b, flags: 17, parent: ext, nameAt: name)
            b.align(4)
            let list = b.count, slot = b.relSlot()
            b.patchRel(slot, nested)
            let mangled = b.count
            b.data.append(contentsOf: bytes)
            b.patchRel(ext + 8, mangled)
            let types = SwiftMetadataParser(data: Data(b.data), sections: [
                .init(name: "__swift5_types", address: UInt64(list), fileOffset: UInt64(list), size: 4),
                .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(list)),
                .init(name: "__const", address: UInt64(list + 4), fileOffset: UInt64(list + 4), size: UInt64(b.count - (list + 4))),
            ]).parseTypes()
            XCTAssertEqual(types.map(\.name), ["Nested"])
            XCTAssertEqual(types.map(\.qualifiedName), [nil])
        }
    }

    func testParentCycleAndMissingModuleLeaveQualifiedNameNilNotGuessed() {
        var b = ImageBuilder()
        let nameAt = b.cstring("Lost")
        let orphan = contextDescriptor(&b, flags: 17, parent: nil, nameAt: nameAt)
        b.align(4)
        let loop = b.count
        b.u32(17); let selfSlot = b.relSlot(), loopName = b.relSlot(); b.u32(0); b.u32(0); b.u32(0); b.u32(0)
        b.patchRel(selfSlot, loop); b.patchRel(loopName, nameAt)
        let types = parseTypes(&b, entries: [orphan, loop])
        XCTAssertEqual(types.map(\.name), ["Lost", "Lost"])
        XCTAssertEqual(types.map(\.qualifiedName), [nil, nil])
    }

    /// Conformance descriptor: protocol@0 (RelativeIndirectablePointer), typeRef@4, witness@8, flags@12.
    func testProtocolFromAnotherModuleIsQualifiedOnlyWhenTheBoundSymbolResolves() {
        var b = ImageBuilder()
        let mod = b.cstring("Mod"), pointName = b.cstring("Point"), orphanName = b.cstring("Orphan")
        let module = contextDescriptor(&b, flags: 0, parent: nil, nameAt: mod)
        let point = contextDescriptor(&b, flags: 17, parent: module, nameAt: pointName)
        let orphanProtocol = contextDescriptor(&b, flags: 3, parent: nil, nameAt: orphanName)
        b.align(8)
        let slotOther = b.count; b.u32(0); b.u32(0)      // GOT slots for bound protocol descriptors
        let slotEquatable = b.count; b.u32(0); b.u32(0)
        let slotOpaque = b.count; b.u32(0); b.u32(0)
        func conformance(protocolTarget: Int, indirect: Bool) -> Int {
            b.align(4)
            let at = b.count
            let protocolSlot = b.relSlot(), typeSlot = b.relSlot()
            b.u32(0); b.u32(0)
            b.patchRel(protocolSlot, protocolTarget)
            if indirect {   // set the indirection bit on the stored relative value
                let raw = Int32(protocolTarget - protocolSlot) | 1
                let bits = UInt32(bitPattern: raw)
                for i in 0..<4 { b.data[protocolSlot + i] = UInt8((bits >> (8 * i)) & 0xff) }
            }
            b.patchRel(typeSlot, point)
            return at
        }
        let cOther = conformance(protocolTarget: slotOther, indirect: true)
        let cEquatable = conformance(protocolTarget: slotEquatable, indirect: true)
        let cLocal = conformance(protocolTarget: orphanProtocol, indirect: false)
        b.align(4)
        let list = b.count
        for entry in [cOther, cEquatable, cLocal] { let slot = b.relSlot(); b.patchRel(slot, entry) }
        _ = slotOpaque
        let parser = SwiftMetadataParser(data: Data(b.data), sections: [
            .init(name: "__swift5_proto", address: UInt64(list), fileOffset: UInt64(list), size: 12),
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(list)),
        ], bindNames: [UInt64(slotOther): "_$s8OtherMod5ProtoMp", UInt64(slotEquatable): "_$sSQMp"])
        let found = parser.parseConformances()
        XCTAssertEqual(found.map(\.protocolName), ["Proto", "Equatable", "Orphan"])
        XCTAssertEqual(found.map(\.protocolQualifiedName), ["OtherMod.Proto", "Swift.Equatable", nil])
        XCTAssertEqual(found.map(\.typeName), ["Point", "Point", "Point"])
        XCTAssertEqual(found.map(\.typeQualifiedName), ["Mod.Point", "Mod.Point", "Mod.Point"])
    }

    func testBoundSymbolLengthAtIntMaxIsRejectedWithoutOverflow() {
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName("_$s9223372036854775807Mn", suffix: "Mn"))
    }

    func testBoundSymbolOrdinaryAndStdlibIdentifiersRemainExact() {
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("$s7QCorpus5PlainV6NestedVMn", suffix: "Mn"),
                       "QCorpus.Plain.Nested")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName("$s7QCorpus5PlainV6NestedVMn", suffix: "Mn"),
                       "Nested")
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("$sSQMp", suffix: "Mp"), "Swift.Equatable")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName("$sSQMp", suffix: "Mp"), "Equatable")
    }

    func testBoundSymbolQualificationNeverGuessesAModule() {
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("_$sSHMp", suffix: "Mp"), "Swift.Hashable")
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("_$s23CustomStringConvertibleMp", suffix: "Mp"), nil)
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("_$ss23CustomStringConvertibleMp", suffix: "Mp"),
                       "Swift.CustomStringConvertible")
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("_$s5MyMod5OuterC5InnerVMn", suffix: "Mn"),
                       "MyMod.Outer.Inner")
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName("_$s5MyMod5OuterCyxGMp", suffix: "Mp"))
    }

    func testBoundSymbolWordSubstitutionRealDescriptors() {
        let cases = [
            ("$s3SIL017ConvertEscapeToNoC4InstCMn", "SIL.ConvertEscapeToNoEscapeInst", "ConvertEscapeToNoEscapeInst"),
            ("$s20_CompilerSwiftSyntax04DeclC8ProtocolMp", "_CompilerSwiftSyntax.DeclSyntaxProtocol", "DeclSyntaxProtocol"),
            ("$s20_CompilerSwiftSyntax03RawC4DataV6LayoutVMn", "_CompilerSwiftSyntax.RawSyntaxData.Layout", "Layout"),
        ]
        for (symbol, qualified, simple) in cases {
            let suffix = String(symbol.suffix(2))
            for spelling in [symbol, "_" + symbol] {
                XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(spelling, suffix: suffix), qualified, spelling)
                XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(spelling, suffix: suffix), simple, spelling)
            }
        }
    }

    func testBoundSymbolWordDictionaryCarriesAcrossIdentifiers() {
        let symbol = "$s6AbcDef0B0V0A0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "AbcDef.Def.Abc")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Abc")
    }

    func testBoundSymbolLowercaseWordReferencesContinue() {
        let symbol = "$s9AbcDefGHI02Myac1_B0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "AbcDefGHI.MyAbcGHI_Def")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "MyAbcGHI_Def")
    }

    func testBoundSymbolUppercaseWordReferenceAllowsLiteralTail() {
        let symbol = "$s6AbcDef0B4TailVMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "AbcDef.DefTail")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "DefTail")
    }

    func testBoundSymbolFinalWordReferenceConsumesZero() {
        let symbol = "$s6AbcDef0A0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "AbcDef.Abc")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Abc")
    }

    func testBoundSymbolLiteralWordsRequireTwoCharacters() {
        let symbol = "$s5A_Bcd0A0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "A_Bcd.Bcd")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Bcd")
    }

    func testBoundSymbolDuplicateWordsKeepDistinctIndices() {
        let symbol = "$s8AbAb_Zed0C0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "AbAb_Zed.Zed")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Zed")
    }

    func testBoundSymbolWordsSplitAtUnderscoresAndCamelCase() {
        let symbol = "$s11Abc1DefG2HI0abcdA0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "Abc1DefG2HI.Abc1DefG2HIAbc1")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Abc1DefG2HIAbc1")
    }

    func testBoundSymbolDigitsDoNotStartWords() {
        let symbol = "$s8_12Ab3Cd0A0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "_12Ab3Cd.Ab3")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Ab3")
    }

    func testBoundSymbolDollarCanStartAWord() {
        let symbol = "$s6$abDef0A0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "$abDef.$ab")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "$ab")
    }

    func testBoundSymbolWordsAreCollectedFromSeparateLiteralSlices() {
        let symbol = "$s6AbcDef02HiA2LoV0D0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "AbcDef.HiAbcLo.Lo")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Lo")
    }

    func testBoundSymbolWordDictionaryStopsAtTwentySix() {
        let module = (0...26).map { String(format: "W%02d", $0) }.joined(separator: "_")
        let symbol = "$s\(module.utf8.count)\(module)0Z0VMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), module + ".W25")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "W25")
    }

    func testBoundSymbolSubstitutedWordsAreNotRegisteredAgain() {
        let symbol = "$s6AbcDef0A0V0C0VMn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolWordDictionaryResetsForEachSymbol() {
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName("$s6AbcDef0B0VMn", suffix: "Mn"), "AbcDef.Def")
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName("$s2Hi0B0VMn", suffix: "Mn"))
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName("$s6AbcDef0B0VMn", suffix: "Mn"), "Def")
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName("$s2Hi0B0VMn", suffix: "Mn"))
    }

    func testBoundSymbolRejectsUnknownWordIndex() {
        let symbol = "$s6AbcDef0Z0VMn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolRejectsMissingFinalWordTail() {
        let symbol = "$s6AbcDef0AVMn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolRejectsTruncatedLiteralSlice() {
        let symbol = "$s6AbcDef03HiMn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolRejectsEmptyCompressedIdentifier() {
        let symbol = "$s6AbcDef0Mn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolRejectsOverflowingIdentifierLength() {
        let symbol = "$s92233720368547758070Mn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolPunycodeIsNotAWordSubstitution() {
        let symbol = "$s3Mod003abcVMn"
        XCTAssertNil(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"))
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"))
    }

    func testBoundSymbolInteriorZeroRemainsAnOrdinaryIdentifier() {
        let symbol = "$s10Foundation20ISO8601DateFormatterC7OptionsVMn"
        XCTAssertEqual(SwiftMetadataParser._qualifiedBoundSymbolName(symbol, suffix: "Mn"), "Foundation.ISO8601DateFormatter.Options")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(symbol, suffix: "Mn"), "Options")
    }

    func testBoundSymbolSimpleNameDeclinesPrivateDiscriminator() {
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(
            "$s3Mod4Name33_12345678901234567890123456789012LLVMn", suffix: "Mn"))
    }

    func testBoundSymbolSimpleNameDeclinesLocalContext() {
        XCTAssertNil(SwiftMetadataParser._extractBoundSymbolName(
            "$s7QCorpus10localTypesSayypXpGyF5LocalL_V6NestedVMn", suffix: "Mn"))
    }

    func testBoundSymbolSimpleNameRetainsFirstIdentifierSubstitution() {
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName("$s6XCTestAACMn", suffix: "Mn"), "XCTest")
        XCTAssertEqual(SwiftMetadataParser._extractBoundSymbolName(
            "$s11Observation0A9RegistrarV5State33_5AE0855755CD62D4521FC18D42BC1E4BLLVAAVMn", suffix: "Mn"),
            "Observation")
    }

    // MARK: - Bounds safety on hostile / empty input (never crash, never fabricate)

    func testEmptyAndMissingSectionsYieldNoTypes() {
        XCTAssertTrue(SwiftMetadataParser(data: Data(), sections: []).parseTypes().isEmpty)
        // A types section whose relative pointers dangle far past the buffer must not crash.
        let sec = SwiftMetadataParser.Section(name: "__swift5_types", address: 0, fileOffset: 0, size: 16)
        let garbage = Data([0xff, 0xff, 0xff, 0x7f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd])
        XCTAssertTrue(SwiftMetadataParser(data: garbage, sections: [sec]).parseTypes().isEmpty)
    }

    func testTruncatedDescriptorDoesNotCrash() {
        // __swift5_types entry points to a descriptor that runs off the end of the buffer.
        var b = ImageBuilder()
        b.align(4)
        let tyv = b.count
        let entry = b.relSlot()
        b.patchRel(entry, b.count + 4)   // points just past EOF
        let sections = [
            SwiftMetadataParser.Section(name: "__swift5_types", address: UInt64(tyv), fileOffset: UInt64(tyv), size: 4),
            SwiftMetadataParser.Section(name: "__const", address: 0, fileOffset: 0, size: UInt64(tyv)),
        ]
        XCTAssertTrue(SwiftMetadataParser(data: Data(b.data), sections: sections).parseTypes().isEmpty)
    }

    func testSuperclassSymbolicResolutionControlsAuthorityAndFrontier() throws {
        var b = ImageBuilder()
        let mod = b.cstring("Mod"), baseName = b.cstring("Base"), childName = b.cstring("Child")
        let module = contextDescriptor(&b, flags: 0, parent: nil, nameAt: mod)
        let base = contextDescriptor(&b, flags: 16, parent: module, nameAt: baseName)
        let child = contextDescriptor(&b, flags: 16, parent: module, nameAt: childName)
        b.align(8)
        let got = b.count
        b.u32(0); b.u32(0)
        let mangled = b.count
        b.byte(0x02); let reference = b.relSlot(); b.byte(0)
        b.patchRel(reference, got)
        b.patchRel(child + 20, mangled)
        b.align(4)
        let list = b.count, slot = b.relSlot()
        b.patchRel(slot, child)
        let sections: [SwiftMetadataParser.Section] = [
            .init(name: "__swift5_types", address: UInt64(list), fileOffset: UInt64(list), size: 4),
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(list)),
        ]
        for resolved in [false, true] {
            let types = SwiftMetadataParser(data: Data(b.data), sections: sections,
                rebaseTargets: resolved ? [UInt64(got): UInt64(base)] : [:]).parseTypes()
            XCTAssertEqual(types.map(\.name), ["Child"])
            XCTAssertEqual(types.first?.superclass, resolved ? "Base" : "…")
            XCTAssertEqual(types.first?.superclassUnresolvedReason, resolved ? nil : "needsFixup")
            let output = SwiftMetadataFactProjection.project(types: types, conformances: [], diagnostics: [],
                                                            image: "Fixture", toolchain: "test")
            XCTAssertEqual(output.refused, [])
            let facts = output.facts.filter { $0.predicate == "superclass" }
            XCTAssertEqual(facts.map(\.value), [resolved ? .string("Base") : .null])
            XCTAssertEqual(facts.map(\.status), [resolved ? "authoritative" : "unknown"])
            XCTAssertEqual(output.frontier.map(\.gap), resolved ? [] : ["unknownType"])
            XCTAssertEqual(output.frontier.map(\.detail), resolved ? [] : ["superclass; mangled …; reason needsFixup"])
        }
    }

    // MARK: - N1 facts (superclass, isGeneric, isPrivateOrLocal, isImportedCType, isProtocol)

    /// Hand-laid image: module `__C` → class `Imp` (generic, mangled superclass); module `Mod` →
    /// anonymous context → struct `Hidden`; module `Mod` → plain class `Root` (no superclass); a
    /// protocol descriptor listed in `__swift5_protos`.
    private func factsFixture() -> (parser: SwiftMetadataParser, imp: UInt64, hidden: UInt64, root: UInt64, proto: UInt64) {
        var b = ImageBuilder()
        let cName = b.cstring("__C"), modName = b.cstring("Mod")
        let impName = b.cstring("Imp"), hiddenName = b.cstring("Hidden")
        let rootName = b.cstring("Root"), protoName = b.cstring("Speaker")
        let superMangled = b.cstring("So8NSObjectC")
        b.align(4)
        func descriptor(flags: UInt32, parent: Int?, name: Int, extra: Int = 0) -> Int {
            let at = b.count
            b.u32(flags)
            let p = b.relSlot(); let n = b.relSlot()
            b.u32(0); b.u32(0)                       // AccessFunction, Fields
            for _ in 0..<extra { b.u32(0) }
            if let parent { b.patchRel(p, parent) }
            b.patchRel(n, name)
            return at
        }
        let cMod = descriptor(flags: 0, parent: nil, name: cName)
        let mod = descriptor(flags: 0, parent: nil, name: modName)
        let anon = descriptor(flags: 2, parent: mod, name: modName)   // name slot unused for anonymous
        let imp = descriptor(flags: 16 | 0x80, parent: cMod, name: impName, extra: 1)
        b.patchRel(imp + 20, superMangled)
        let hidden = descriptor(flags: 17, parent: anon, name: hiddenName, extra: 1)
        let root = descriptor(flags: 16, parent: mod, name: rootName, extra: 1)
        let proto = descriptor(flags: 3, parent: mod, name: protoName)
        let types = b.count
        for target in [imp, hidden, root] { let slot = b.relSlot(); b.patchRel(slot, target) }
        let protos = b.count
        let protoSlot = b.relSlot(); b.patchRel(protoSlot, proto)
        let parser = SwiftMetadataParser(data: Data(b.data), sections: [
            .init(name: "__swift5_types", address: UInt64(types), fileOffset: UInt64(types), size: 12),
            .init(name: "__swift5_protos", address: UInt64(protos), fileOffset: UInt64(protos), size: 4),
            .init(name: "__const", address: 0, fileOffset: 0, size: UInt64(types)),
        ])
        return (parser, UInt64(imp), UInt64(hidden), UInt64(root), UInt64(proto))
    }

    func testHermeticFactsPerType() throws {
        let f = factsFixture()
        let byAddress = Dictionary(uniqueKeysWithValues: f.parser.parseTypes().map { ($0.descriptorAddress!, $0) })
        let imp = try XCTUnwrap(byAddress[f.imp]), hidden = try XCTUnwrap(byAddress[f.hidden]), root = try XCTUnwrap(byAddress[f.root])
        XCTAssertEqual(imp.isGeneric, true)
        XCTAssertEqual(imp.isImportedCType, true)
        XCTAssertEqual(imp.isPrivateOrLocal, false)
        XCTAssertEqual(imp.superclass, "So8NSObjectC")
        XCTAssertEqual(hidden.isPrivateOrLocal, true)
        XCTAssertEqual(hidden.isImportedCType, false)
        XCTAssertEqual(hidden.isGeneric, false)
        XCTAssertNil(hidden.superclass, "a struct has no superclass")
        XCTAssertEqual(root.isGeneric, false)
        XCTAssertEqual(root.isPrivateOrLocal, false)
        XCTAssertEqual(root.isImportedCType, false)
        XCTAssertNil(root.superclass, "a null SuperclassType is a root class")
    }

    func testHermeticProtocolsFromSwift5Protos() {
        let f = factsFixture()
        XCTAssertEqual(f.parser.parseProtocols(), [SwiftProtocolDescriptor(name: "Speaker", descriptorAddress: f.proto)])
        XCTAssertEqual(SwiftMetadataParser(data: Data(), sections: []).parseProtocols(), [])
    }

    func testRealBinaryFactsMatchSourceDeclarations() throws {
        let data = try RealSwiftBinary.build(source: """
        public class Base { var a: Int = 0 }
        public class Child: Base { var b: Int = 0 }
        public struct Gen<T> { let value: T }
        private struct Hidden { let tag: Int }
        public struct Plain { let tag: Int }
        public func use() -> Int { Hidden(tag: 1).tag }
        """)
        let machO = try MachOParser().parse(data, options: MachOParseOptions(
            recoverStringLiterals: false, recoverObjectiveCMetadata: false,
            recoverSwiftMetadata: true, parseCodeSignature: false))
        let byName = Dictionary(uniqueKeysWithValues: machO.swiftTypes.map { ($0.name, $0) })
        XCTAssertNil(byName["Base"]?.superclass)
        XCTAssertEqual(byName["Child"]?.superclass, "Base")
        XCTAssertEqual(byName["Gen"]?.isGeneric, true)
        XCTAssertEqual(byName["Plain"]?.isGeneric, false)
        XCTAssertEqual(byName["Hidden"]?.isPrivateOrLocal, true)
        XCTAssertEqual(byName["Plain"]?.isPrivateOrLocal, false)
        XCTAssertEqual(byName["Plain"]?.isImportedCType, false)
    }

    // MARK: - Real compiled Swift binary (the ground-truth oracle; skipped if swiftc absent)

    func testRecoversTypesFromRealSwiftBinary() throws {
        let data = try RealSwiftBinary.build(source: """
        public struct Point { public let x: Int; public let y: Double; let label: String }
        public class Widget { var count: Int32 = 0; let name: String = "" }
        public enum Color { case red; case green; case rgb(UInt8, UInt8, UInt8) }
        """)
        let machO = try MachOParser().parse(data, options: MachOParseOptions(
            recoverStringLiterals: false,
            recoverObjectiveCMetadata: false,
            recoverSwiftMetadata: true,
            parseCodeSignature: false
        ))
        let byName = Dictionary(uniqueKeysWithValues: machO.swiftTypes.map { ($0.name, $0) })

        let point = try XCTUnwrap(byName["Point"], "Point struct not recovered")
        XCTAssertEqual(point.kind, .struct)
        XCTAssertEqual(point.fields.map(\.name), ["x", "y", "label"])
        XCTAssertEqual(point.fields.map(\.typeName), ["Int", "Double", "String"])
        XCTAssertEqual(point.fields.allSatisfy { !$0.isVar }, true, "Point's fields are all `let`")

        let widget = try XCTUnwrap(byName["Widget"], "Widget class not recovered")
        XCTAssertEqual(widget.kind, .class)
        let widgetFields = Dictionary(uniqueKeysWithValues: widget.fields.map { ($0.name, $0) })
        XCTAssertEqual(widgetFields["count"]?.isVar, true, "`var count` must be marked var")
        XCTAssertEqual(widgetFields["name"]?.typeName, "String")

        let color = try XCTUnwrap(byName["Color"], "Color enum not recovered")
        XCTAssertEqual(color.kind, .enum)
        XCTAssertEqual(Set(color.fields.map(\.name)), ["red", "green", "rgb"])
    }

    /// Adversarial edge cases on real compiler output: in-module type references must RESOLVE
    /// (the direct symbolic-reference path), computed properties must be EXCLUDED (only stored
    /// fields have records), pure stdlib structural types decode through the demangler, resolvable
    /// symbolic-reference compounds preserve their surrounding shape, and generic parameters must
    /// yield `nil` rather than a fabricated type.
    func testAdversarialEdgeCasesFromRealSwiftBinary() throws {
        let data = try RealSwiftBinary.build(source: """
        public struct Inner { let tag: Int }
        public struct Outer { let inner: Inner; var items: [String]; let maybe: Int?; let count: Int }
        public struct Computed { let stored: Int; var doubled: Int { stored * 2 } }
        public final class Box<T> { let value: T; let fixed: Int; public init(_ v: T) { value = v; fixed = 0 } }
        public struct Wrapped { let solo: Inner; let many: [Inner]; let opt: Inner? }
        """)
        let machO = try MachOParser().parse(data, options: MachOParseOptions(
            recoverStringLiterals: false, recoverObjectiveCMetadata: false,
            recoverSwiftMetadata: true, parseCodeSignature: false))
        let byName = Dictionary(uniqueKeysWithValues: machO.swiftTypes.map { ($0.name, $0) })

        // In-module type reference resolves to the referenced type's name (direct symbolic ref).
        let outer = try XCTUnwrap(byName["Outer"])
        let outerFields = Dictionary(uniqueKeysWithValues: outer.fields.map { ($0.name, $0) })
        XCTAssertEqual(outerFields["inner"]?.typeName, "Inner", "in-module type ref must resolve to Inner")
        XCTAssertEqual(outerFields["count"]?.typeName, "Int")
        // Pure stdlib structural field types decode through the bare-type demangler.
        XCTAssertEqual(outerFields["items"]?.typeName, "[String]")
        XCTAssertEqual(outerFields["maybe"]?.typeName, "Int?")

        // Computed properties have NO field record → only the stored property appears.
        let computed = try XCTUnwrap(byName["Computed"])
        XCTAssertEqual(computed.fields.map(\.name), ["stored"], "computed `doubled` must be excluded")

        // A generic type is recovered by name; its concrete field resolves, the type-param does not.
        let box = try XCTUnwrap(byName["Box"])
        let boxFields = Dictionary(uniqueKeysWithValues: box.fields.map { ($0.name, $0) })
        XCTAssertEqual(boxFields["fixed"]?.typeName, "Int")
        XCTAssertNil(boxFields["value"]?.typeName, "generic param T must not be fabricated")

        // Embedded symbolic references resolve only through a full text splice, never by reporting
        // the bare inner type for the surrounding compound shape.
        let wrapped = try XCTUnwrap(byName["Wrapped"])
        let wrappedFields = Dictionary(uniqueKeysWithValues: wrapped.fields.map { ($0.name, $0) })
        XCTAssertEqual(wrappedFields["solo"]?.typeName, "Inner", "bare in-module reference resolves")
        XCTAssertEqual(wrappedFields["many"]?.typeName, "[Inner]")
        XCTAssertEqual(wrappedFields["opt"]?.typeName, "Inner?")
    }

    /// A crafted section whose VA→file-offset projection lands at/near `Int.max` must yield no
    /// types rather than trap on an `off + 4` arithmetic overflow (the never-crash contract).
    func testHugeSectionOffsetDoesNotTrap() {
        let base = UInt64(Int.max) - 10
        let entry: [UInt8] = [8, 0, 0, 0]   // i32 = 8 → descriptor VA = base + 8 (≈ Int.max)
        let sections = [
            SwiftMetadataParser.Section(name: "__swift5_types", address: base, fileOffset: 0, size: 4),
            SwiftMetadataParser.Section(name: "__cover", address: 0, fileOffset: 0, size: UInt64(Int.max)),
        ]
        XCTAssertTrue(SwiftMetadataParser(data: Data(entry), sections: sections).parseTypes().isEmpty)
    }

    func testWideSymbolicReferencePayloadDoesNotDesyncTrailingText() {
        var b = ImageBuilder()
        let fieldName = b.cstring("wide")
        let mangled = b.mangledBytes([0x18, 0, 0, 0, 0, 0, 0, 0, 0] + Array("Sg".utf8))
        let nameOff = b.cstring("WidePayload")
        b.align(4)

        let fd = b.count
        b.u32(0); b.u32(0)
        b.u16(0); b.u16(12)
        b.u32(1)
        b.u32(0); let r0mt = b.relSlot(); let r0fn = b.relSlot()

        b.align(4)
        let td = b.count
        b.u32(17); b.u32(0)
        let tdName = b.relSlot(); b.u32(0); let tdFields = b.relSlot()
        b.u32(1); b.u32(0)

        b.align(4)
        let tyv = b.count
        let tyEntry = b.relSlot()

        b.patchRel(r0mt, mangled)
        b.patchRel(r0fn, fieldName)
        b.patchRel(tdName, nameOff)
        b.patchRel(tdFields, fd)
        b.patchRel(tyEntry, td)

        let sections = [
            SwiftMetadataParser.Section(name: "__swift5_types", address: UInt64(tyv), fileOffset: UInt64(tyv), size: 4),
            SwiftMetadataParser.Section(name: "__const", address: 0, fileOffset: 0, size: UInt64(tyv)),
        ]
        let type = SwiftMetadataParser(data: Data(b.data), sections: sections).parseTypes().first
        XCTAssertEqual(type?.fields.first?.typeName, nil)
        XCTAssertEqual(type?.fields.first?.mangledTypeName, "…Sg")
    }

    func testSymbolicReferenceParentMustTerminateAtModule() {
        var b = ImageBuilder()
        let fieldName = b.cstring("bad")
        let hostName = b.cstring("Host")
        let moduleName = b.cstring("TrapMod")
        let localName = b.cstring("FunctionLocal")
        b.align(4)

        let mangled = b.count
        b.byte(0x01)
        let symPayload = b.relSlot()
        b.byte(0)

        b.align(4)
        let module = b.count
        b.u32(0); b.u32(0)
        let moduleNameSlot = b.relSlot(); b.u32(0); b.u32(0)

        b.align(4)
        let anonymousContext = b.count
        b.u32(2)
        let anonymousParent = b.relSlot()
        b.u32(0); b.u32(0); b.u32(0)

        b.align(4)
        let functionLocal = b.count
        b.u32(17)
        let localParent = b.relSlot()
        let localNameSlot = b.relSlot()
        b.u32(0); b.u32(0)
        b.u32(0); b.u32(0)

        let fd = b.count
        b.u32(0); b.u32(0)
        b.u16(0); b.u16(12)
        b.u32(1)
        b.u32(0); let r0mt = b.relSlot(); let r0fn = b.relSlot()

        b.align(4)
        let host = b.count
        b.u32(17); b.u32(0)
        let hostNameSlot = b.relSlot(); b.u32(0); let hostFields = b.relSlot()
        b.u32(1); b.u32(0)

        b.align(4)
        let tyv = b.count
        let tyEntry = b.relSlot()

        b.patchRel(symPayload, functionLocal)
        b.patchRel(moduleNameSlot, moduleName)
        b.patchRel(anonymousParent, module)
        b.patchRel(localParent, anonymousContext)
        b.patchRel(localNameSlot, localName)
        b.patchRel(r0mt, mangled)
        b.patchRel(r0fn, fieldName)
        b.patchRel(hostNameSlot, hostName)
        b.patchRel(hostFields, fd)
        b.patchRel(tyEntry, host)

        let sections = [
            SwiftMetadataParser.Section(name: "__swift5_types", address: UInt64(tyv), fileOffset: UInt64(tyv), size: 4),
            SwiftMetadataParser.Section(name: "__const", address: 0, fileOffset: 0, size: UInt64(tyv)),
        ]
        let type = SwiftMetadataParser(data: Data(b.data), sections: sections).parseTypes().first
        XCTAssertEqual(type?.fields.first?.typeName, nil)
        XCTAssertEqual(type?.fields.first?.mangledTypeName, "…")
    }

    // MARK: Symbolic-reference field types

    private enum RefPart {
        case text(String)
        case target(UInt8)   // control byte 0x01 → relative pointer straight to the Target descriptor
        case slot(UInt8)     // control byte 0x02 → relative pointer to an 8-byte GOT slot
    }

    /// One struct `Host` with a single field whose mangled name is `parts`. `Mod.Target` is a struct
    /// descriptor in the image; the GOT slot is wired by `fixup` (a rebase to Target, a bind to a
    /// symbol, or nothing).
    private enum SlotFixup { case rebaseToTarget, bind(String), none }

    private func parseSymbolicField(_ parts: [RefPart], fixup: SlotFixup = .none) -> SwiftField? {
        var b = ImageBuilder()
        let fieldName = b.cstring("f")
        let hostName = b.cstring("Host")
        let targetName = b.cstring("Target")
        let moduleName = b.cstring("Mod")
        b.align(4)

        let module = b.count
        b.u32(0); b.u32(0)
        let moduleNameSlot = b.relSlot(); b.u32(0); b.u32(0)

        b.align(4)
        let target = b.count
        b.u32(17)
        let targetParent = b.relSlot()
        let targetNameSlot = b.relSlot()
        b.u32(0); b.u32(0)

        b.align(8)
        let got = b.count
        b.u32(0); b.u32(0)

        let mangled = b.count
        var refSlots: [(slot: Int, toTarget: Bool)] = []
        for part in parts {
            switch part {
            case .text(let text): b.data.append(contentsOf: Array(text.utf8))
            case .target(let control): b.byte(control); refSlots.append((b.relSlot(), true))
            case .slot(let control): b.byte(control); refSlots.append((b.relSlot(), false))
            }
        }
        b.byte(0)

        b.align(4)
        let fd = b.count
        b.u32(0); b.u32(0)
        b.u16(0); b.u16(12)
        b.u32(1)
        b.u32(0); let r0mt = b.relSlot(); let r0fn = b.relSlot()

        b.align(4)
        let host = b.count
        b.u32(17); b.u32(0)
        let hostNameSlot = b.relSlot(); b.u32(0); let hostFields = b.relSlot()
        b.u32(1); b.u32(0)

        b.align(4)
        let tyv = b.count
        let tyEntry = b.relSlot()

        for ref in refSlots { b.patchRel(ref.slot, ref.toTarget ? target : got) }
        b.patchRel(moduleNameSlot, moduleName)
        b.patchRel(targetParent, module)
        b.patchRel(targetNameSlot, targetName)
        b.patchRel(r0mt, mangled)
        b.patchRel(r0fn, fieldName)
        b.patchRel(hostNameSlot, hostName)
        b.patchRel(hostFields, fd)
        b.patchRel(tyEntry, host)

        var rebase: [UInt64: UInt64] = [:]
        var binds: [UInt64: String] = [:]
        switch fixup {
        case .rebaseToTarget: rebase[UInt64(got)] = UInt64(target)
        case .bind(let symbol): binds[UInt64(got)] = symbol
        case .none: break
        }
        let sections = [
            SwiftMetadataParser.Section(name: "__swift5_types", address: UInt64(tyv), fileOffset: UInt64(tyv), size: 4),
            SwiftMetadataParser.Section(name: "__const", address: 0, fileOffset: 0, size: UInt64(tyv)),
        ]
        return SwiftMetadataParser(data: Data(b.data), sections: sections, rebaseTargets: rebase, bindNames: binds)
            .parseTypes().first(where: { $0.name == "Host" })?.fields.first
    }

    func testDirectSymbolicReferenceResolvesToTypeName() {
        let field = parseSymbolicField([.target(0x01)])
        XCTAssertEqual(field?.typeName, "Target")
        XCTAssertNil(field?.unresolvedReason)
    }

    func testIndirectSymbolicReferenceResolvesThroughRebasedSlot() {
        let field = parseSymbolicField([.slot(0x02)], fixup: .rebaseToTarget)
        XCTAssertEqual(field?.typeName, "Target")
        XCTAssertNil(field?.unresolvedReason)
    }

    func testIndirectSymbolicReferenceResolvesThroughBoundExternalDescriptor() {
        let field = parseSymbolicField([.slot(0x02)], fixup: .bind("_$s10Foundation3URLVMn"))
        XCTAssertEqual(field?.typeName, "URL")
    }

    func testBoundExternalProtocolRestoresKindAndPreservesNominalAndStdlibNames() throws {
        XCTAssertEqual(SwiftDemangler.demangleType("8OtherMod5ProtoP"), "OtherMod.Proto")
        for (symbol, expected) in [("$s8OtherMod5ProtoMp", "Proto"),
                                   ("_$s10Foundation3URLVMn", "URL"), ("$sSQMp", "Equatable")] {
            let field = try XCTUnwrap(parseSymbolicField([.slot(0x02)], fixup: .bind(symbol)))
            // Field display names omit a module only after the full descriptor path resolves.
            XCTAssertEqual(field.typeName, expected, symbol)
            XCTAssertEqual(field.mangledTypeName, "…", symbol)
            XCTAssertNil(field.unresolvedReason, symbol)
        }
    }

    func testBoundExternalConcurrencyProtocolSubstitutions() throws {
        // Swift 6.3 StandardTypesMangling.def: second-level Protocol entries.
        for (body, expected) in [("ScA", "Actor"), ("ScF", "Executor"),
                                 ("Scf", "SerialExecutor"), ("Sch", "TaskExecutor"),
                                 ("ScI", "AsyncIteratorProtocol"), ("Sci", "AsyncSequence")] {
            for prefix in ["$s", "_$s"] {
                let symbol = prefix + body + "Mp"
                let field = try XCTUnwrap(parseSymbolicField([.slot(0x02)], fixup: .bind(symbol)))
                XCTAssertEqual(field.typeName, expected, symbol)
                XCTAssertEqual(field.mangledTypeName, "…", symbol)
                XCTAssertNil(field.unresolvedReason, symbol)
            }
        }
    }

    func testBoundExternalConcurrencyProtocolSubstitutionsRejectInvalidBodies() {
        for symbol in ["$sScMp", "$sScZMp", "$sScAPMp", "$sScAMpX",
                       "$sScA\u{01}Mp", "$sScTMp", "$sScMMp"] {
            let field = parseSymbolicField([.slot(0x02)], fixup: .bind(symbol))
            XCTAssertNil(field?.typeName, symbol)
            XCTAssertEqual(field?.unresolvedReason, "unresolvedDescriptor", symbol)
        }
    }

    func testIndirectSymbolicReferenceWithoutFixupStaysUnresolvedWithReason() {
        let field = parseSymbolicField([.slot(0x02)], fixup: .none)
        XCTAssertNil(field?.typeName)
        XCTAssertEqual(field?.mangledTypeName, "\u{2026}")
        XCTAssertEqual(field?.unresolvedReason, "needsFixup")
    }

    func testBoundSlotWithUnreadableSymbolStaysUnresolved() {
        let field = parseSymbolicField([.slot(0x02)], fixup: .bind("_objc_msgSend"))
        XCTAssertNil(field?.typeName)
        XCTAssertEqual(field?.unresolvedReason, "unresolvedDescriptor")
    }

    func testUnsupportedSymbolicControlByteIsReportedNotGuessed() {
        let field = parseSymbolicField([.target(0x05)])
        XCTAssertNil(field?.typeName)
        XCTAssertEqual(field?.unresolvedReason, "unsupportedReference")
    }

    func testSymbolicReferenceInsideGenericArgumentSplices() {
        XCTAssertEqual(parseSymbolicField([.text("Say"), .target(0x01), .text("G")])?.typeName, "[Target]")
        XCTAssertEqual(parseSymbolicField([.text("Say"), .slot(0x02), .text("G")], fixup: .rebaseToTarget)?.typeName, "[Target]")
        XCTAssertNil(parseSymbolicField([.text("Say"), .slot(0x02), .text("G")])?.typeName)
    }
}

// MARK: - Helpers

/// Builds a flat reflection image where virtual address == file offset, so a self-relative pointer
/// stored at slot `s` pointing at `t` holds exactly `Int32(t - s)`.
struct ImageBuilder {
    var data: [UInt8] = []
    var count: Int { data.count }
    mutating func align(_ n: Int) { while data.count % n != 0 { data.append(0) } }
    mutating func byte(_ v: UInt8) { data.append(v) }
    mutating func u16(_ v: UInt16) { data.append(UInt8(v & 0xff)); data.append(UInt8(v >> 8)) }
    mutating func u32(_ v: UInt32) { for i in 0..<4 { data.append(UInt8((v >> (8 * i)) & 0xff)) } }
    mutating func u64(_ v: UInt64) { for i in 0..<8 { data.append(UInt8((v >> (8 * UInt64(i))) & 0xff)) } }
    mutating func cstring(_ s: String) -> Int { let off = data.count; data.append(contentsOf: Array(s.utf8)); data.append(0); return off }
    mutating func mangledBytes(_ bytes: [UInt8]) -> Int { let off = data.count; data.append(contentsOf: bytes); data.append(0); return off }
    /// Reserves a 4-byte relative-pointer slot (zeroed) and returns its offset for later patching.
    mutating func relSlot() -> Int { let off = data.count; u32(0); return off }
    mutating func patchRel(_ slot: Int, _ target: Int) {
        let bits = UInt32(bitPattern: Int32(target - slot))
        for i in 0..<4 { data[slot + i] = UInt8((bits >> (8 * i)) & 0xff) }
    }
}

/// Compiles a tiny Swift module to a dylib (with reflection metadata) and returns its bytes.
/// Skips the test if `xcrun swiftc` is unavailable on the host.
private enum RealSwiftBinary {
    static func build(source sourceText: String) throws -> Data {
        let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
        guard FileManager.default.isExecutableFile(atPath: xcrun.path) else {
            throw XCTSkip("xcrun unavailable on this host")
        }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("macscope-swiftmd-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let source = dir.appendingPathComponent("M.swift")
        try sourceText.write(to: source, atomically: true, encoding: .utf8)

        let dylib = dir.appendingPathComponent("libM.dylib")
        try run(xcrun, ["swiftc", "-target", "arm64-apple-macos13", "-emit-library", "-o", dylib.path, source.path])
        guard FileManager.default.fileExists(atPath: dylib.path) else {
            throw XCTSkip("swiftc did not produce a dylib on this host")
        }
        return try Data(contentsOf: dylib)
    }

    private static func run(_ tool: URL, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = tool
        process.arguments = arguments
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = pipe
        try process.run()
        let drain = CoreTestPipeDrain(pipe)
        process.waitUntilExit()
        let output = drain.text()
        if process.terminationStatus != 0 {
            throw XCTSkip("\(tool.lastPathComponent) \(arguments.first ?? "") failed (\(process.terminationStatus)): \(output)")
        }
    }
}
