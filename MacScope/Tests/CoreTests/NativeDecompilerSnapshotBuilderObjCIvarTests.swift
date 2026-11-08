import Foundation
import XCTest
@testable import MacScope

/// Item 1331 (E1): the pure ObjC ivar offset-global planner and its shared-ceiling projection.
/// Every fixture is local and self-contained; each distinct input is produced once.
final class NativeDecompilerSnapshotBuilderObjCIvarTests: XCTestCase {
    private typealias Builder = NativeDecompilerSnapshotBuilder
    private let imageID = "img"
    private let marker = "objc-ivar-metadata"

    // __DATA maps 0x4000..<0x6000 with file bytes for the first 0x1000 (a zero-fill tail follows);
    // __DWARF is file-only (vmsize 0) and maps nothing.
    private func layout() throws -> [Builder.VerifiedSegment] {
        try Builder.verifyLayout([
            MachOPreferredSegmentLayout.Record(
                name: "__DATA", preferredVMStart: 0x4000, preferredVMSize: 0x2000,
                sliceRelativeFileOffset: 0, fileSize: 0x1000, initialProtections: 3),
            MachOPreferredSegmentLayout.Record(
                name: "__DWARF", preferredVMStart: 0x9000, preferredVMSize: 0,
                sliceRelativeFileOffset: 0x1000, fileSize: 0x100, initialProtections: 1),
        ], selectedSliceByteCount: 0x2000)
    }

    private func cls(
        _ name: String, address: UInt64? = 0x100, ivars: [(String, UInt64?)]
    ) -> ObjCClass {
        ObjCClass(
            name: name, superclassName: nil, adoptedProtocols: [], classMethods: [], instanceMethods: [],
            ivars: ivars.map { ObjCIvar(name: $0.0, typeEncoding: nil, offsetVariable: $0.1) },
            properties: [], address: address)
    }

    private func real(_ name: String, at address: UInt64?, kind: String = "local") -> SymbolSummary {
        SymbolSummary(id: UUID(), name: name, address: address, kind: kind, libraryName: nil,
                      rawLinkageName: name)
    }

    private func plan(
        _ classes: [ObjCClass], source: [SymbolSummary] = [], functions: [FunctionSummary] = [],
        layout explicit: [Builder.VerifiedSegment]? = nil
    ) throws -> Builder.ObjCIvarSymbolPlan {
        Builder.planObjCIvarOffsetSymbols(
            classes: classes, source: source, functions: functions, imageID: imageID,
            mappedLayout: try explicit ?? layout())
    }

    private let textStorage = "_OBJC_IVAR_$_FixtureDocument.textStorage"
    private let length = "_OBJC_IVAR_$_FixtureDocument.length"

    // MARK: TC01 planner and typed records

    func testPlannerResolvesMarkedExactDataRecordsAndIgnoresInputOrder() throws {
        let classes = [cls("FixtureDocument", ivars: [("textStorage", 0x5000), ("length", 0x5004)])]
        let forward = try plan(classes)
        XCTAssertEqual(forward.candidates.map(\.name), [textStorage, length])
        XCTAssertEqual(forward.candidates.map(\.address.value), [0x5000, 0x5004])
        XCTAssertTrue(forward.candidates.allSatisfy { $0.kind == .data && $0.provenance == marker && $0.imageID == imageID })
        XCTAssertEqual(forward.decisions.map(\.state), [.resolved, .resolved])
        XCTAssertEqual(forward.decisions.map(\.diagnostics), [["provenance=objc-ivar-metadata"], ["provenance=objc-ivar-metadata"]])
        let reversed = try plan([cls("FixtureDocument", ivars: [("length", 0x5004), ("textStorage", 0x5000)])])
        XCTAssertEqual(forward, reversed)
    }

    func testIntactRealEntryIsUnchangedAndNothingIsAdded() throws {
        let result = try plan(
            [cls("FixtureDocument", ivars: [("textStorage", 0x5000)])],
            source: [real(textStorage, at: 0x5000)])
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertEqual(result.decisions.map(\.state), [.unchanged])
        XCTAssertEqual(result.decisions.map(\.diagnostics), [[]])
    }

    func testZeroOrMissingTargetMakesNoClaim() throws {
        let result = try plan([cls("FixtureDocument", ivars: [("a", nil), ("b", 0)])])
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertTrue(result.decisions.isEmpty)
    }

    // MARK: TC04 vetoes, reservations, coalescing

    func testByteIdenticalRepeatedClassEntriesCoalesceButDistinctClassAddressesAbstain() throws {
        let one = cls("C", ivars: [("x", 0x5000)])
        XCTAssertEqual(try plan([one, one]).candidates.map(\.address.value), [0x5000])
        let twin = cls("C", address: 0x200, ivars: [("x", 0x5000)])
        let result = try plan([one, twin])
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertEqual(result.decisions.map(\.state), [.abstain, .abstain])
        XCTAssertEqual(result.decisions.map(\.diagnostics), [["metadata-address-multiple-claimants"], ["metadata-address-multiple-claimants"]])
        let absent = cls("C", address: nil, ivars: [("x", 0x5000)])
        XCTAssertTrue(try plan([one, absent]).candidates.isEmpty, "missing and present class address are distinct")
    }

    func testDistinctClaimantsAtOneAddressAbstain() throws {
        let result = try plan([cls("A", ivars: [("x", 0x5000)]), cls("B", ivars: [("y", 0x5000)])])
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertEqual(result.decisions.map(\.state), [.abstain, .abstain])
    }

    func testOneNameAtTwoMappedAddressesSuppressesBoth() throws {
        let result = try plan([cls("A", ivars: [("x", 0x5000)]), cls("A", address: 0x300, ivars: [("x", 0x5008)])])
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertEqual(Set(result.decisions.flatMap(\.diagnostics)), ["metadata-name-multiple-addresses"])
    }

    func testOutOfMapSamePeerVetoesMappedClaimButNeverEmits() throws {
        let result = try plan([cls("A", ivars: [("x", 0x5000)]), cls("A", address: 0x300, ivars: [("x", 0x7000)])])
        XCTAssertTrue(result.candidates.isEmpty)
        let byAddress = Dictionary(uniqueKeysWithValues: result.decisions.map { ($0.address, $0) })
        XCTAssertEqual(byAddress[0x5000]?.state, .abstain)
        XCTAssertEqual(byAddress[0x7000]?.state, .unchanged)
    }

    func testMalformedCompetitorAtAnEligibleAddressVetoesTheEligibleClaim() throws {
        let result = try plan([cls("A", ivars: [("x", 0x5000)]), cls("B\u{FFFD}", ivars: [("y", 0x5000)])])
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertEqual(result.decisions.filter { $0.state == .abstain }.map(\.address), [0x5000])
    }

    func testMappedGeometryAcceptsZeroFillTailAndRejectsGapsFileOnlyAndShortTail() throws {
        let cases: [(UInt64, Bool)] = [
            (0x4000, true), (0x4800, true), (0x5ffc, true),
            (0x5ffd, false), (0x5fff, false), (0x6000, false),
            (0x3ffc, false), (0x9000, false), (0x9004, false),
        ]
        for (address, expected) in cases {
            let result = try plan([cls("A", ivars: [("x", address)])])
            XCTAssertEqual(result.candidates.count, expected ? 1 : 0, "address \(String(address, radix: 16))")
            XCTAssertEqual(result.decisions.first?.state, expected ? .resolved : .unchanged)
        }
        // A target at the top of the address space must not overflow the width guard.
        XCTAssertTrue(try plan([cls("A", ivars: [("x", UInt64.max - 1)])]).candidates.isEmpty)
    }

    func testRealEntriesAndReservationsDecideInFixedPriority() throws {
        let classes = [cls("A", ivars: [("x", 0x5000)])]
        let name = "_OBJC_IVAR_$_A.x"
        let mismatch = try plan(classes, source: [real("_other", at: 0x5000)])
        XCTAssertTrue(mismatch.candidates.isEmpty)
        XCTAssertEqual(mismatch.decisions.map(\.diagnostics), [["real-address-name-mismatch"]])
        let otherAddress = try plan(classes, source: [real(name, at: 0x5008)])
        XCTAssertEqual(otherAddress.decisions.map(\.diagnostics), [["real-name-other-address"]])
        let unknownAddress = try plan(classes, source: [real(name, at: nil)])
        XCTAssertEqual(unknownAddress.decisions.map(\.diagnostics), [["real-name-other-address"]])
        let function = FunctionSummary(id: UUID(), name: "f", startAddress: 0x5000, endAddress: 0x5004, confidence: 1)
        let reserved = try plan(classes, functions: [function])
        XCTAssertTrue(reserved.candidates.isEmpty)
        XCTAssertEqual(reserved.decisions.map(\.state), [.unchanged])
        let addressedNoRaw = SymbolSummary(id: UUID(), name: "display", address: 0x5000, kind: "local", libraryName: nil)
        XCTAssertEqual(try plan(classes, source: [addressedNoRaw]).decisions.map(\.state), [.unchanged])
        let stub = real("_objc_msgSend$x", at: 0x5000, kind: "stub")
        XCTAssertEqual(try plan(classes, source: [stub]).decisions.map(\.diagnostics), [["real-address-name-mismatch"]])
    }

    // MARK: TC08 exact text

    func testComposedNameBoundariesAndInvalidTextAbstain() throws {
        let prefixBytes = Builder.objCIvarSymbolPrefix.utf8.count
        let ivarLength = 1_024 - prefixBytes - 1 - 1
        let atLimit = try plan([cls("C", ivars: [(String(repeating: "i", count: ivarLength), 0x5000)])])
        XCTAssertEqual(atLimit.candidates.count, 1)
        let over = try plan([cls("C", ivars: [(String(repeating: "i", count: ivarLength + 1), 0x5000)])])
        XCTAssertTrue(over.candidates.isEmpty)
        // Multi-byte text is counted in UTF-8 bytes, not characters.
        let wide = try plan([cls("C", ivars: [(String(repeating: "é", count: ivarLength / 2 + 1), 0x5000)])])
        XCTAssertTrue(wide.candidates.isEmpty)
        for (className, ivarName) in [("", "x"), ("C", ""), ("C\u{FFFD}", "x"), ("C", "x\u{FFFD}"),
                                      ("C\u{1}", "x"), ("C", "x\u{7F}"), ("C", "x\n")] {
            let result = try plan([cls(className, ivars: [(ivarName, 0x5000)])])
            XCTAssertTrue(result.candidates.isEmpty, "\(className.debugDescription) \(ivarName.debugDescription)")
        }
        let unicode = try plan([cls("Ünï", ivars: [("日本", 0x5000)])])
        XCTAssertEqual(unicode.candidates.map(\.name), ["_OBJC_IVAR_$_Ünï.日本"])
    }

    // MARK: TC06 leaf record contract

    func testUnmarkedRecordKeepsFourKeysAndMarkedRecordAddsExactlyOne() throws {
        let unmarked = NativeDecompilerWireSymbolRecord(imageID: "i", address: .init(0x10), name: "n", kind: .data)
        let marked = NativeDecompilerWireSymbolRecord(
            imageID: "i", address: .init(0x10), name: "n", kind: .data, provenance: marker)
        func keys(_ record: NativeDecompilerWireSymbolRecord) throws -> Set<String> {
            let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(record))
            return Set(try XCTUnwrap(object as? [String: Any]).keys)
        }
        XCTAssertEqual(try keys(unmarked), ["imageID", "address", "name", "kind"])
        XCTAssertEqual(try keys(marked), ["imageID", "address", "name", "kind", "provenance"])
        XCTAssertNil(unmarked.provenance)
        XCTAssertNotEqual(unmarked, marked)
        let decoded = try JSONDecoder().decode(
            NativeDecompilerWireSymbolRecord.self, from: JSONEncoder().encode(marked))
        XCTAssertEqual(decoded.provenance, marker)
        let legacy = try JSONDecoder().decode(
            NativeDecompilerWireSymbolRecord.self, from: JSONEncoder().encode(unmarked))
        XCTAssertNil(legacy.provenance)
        let unknown = Data(#"{"imageID":"i","address":"0000000000000010","name":"n","kind":"data","provenance":"other"}"#.utf8)
        XCTAssertEqual(try JSONDecoder().decode(NativeDecompilerWireSymbolRecord.self, from: unknown).provenance, "other")
        let wrongType = Data(#"{"imageID":"i","address":"0000000000000010","name":"n","kind":"data","provenance":7}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(NativeDecompilerWireSymbolRecord.self, from: wrongType))
    }

    // MARK: TC04/TC05 integrated projection and the shared ceiling

    func testProjectionWithOmittedOrEmptyMetadataInputsIsIdentical() throws {
        let source = [real("_OBJC_IVAR_$_A.x", at: 0x5000), real("_f", at: 0x1000)]
        let omitted = try Builder.projectSymbols(source, functions: [], imageID: imageID)
        let empty = try Builder.projectSymbols(
            source, functions: [], imageID: imageID, objcClasses: [], mappedLayout: try layout())
        XCTAssertEqual(omitted, empty)
        XCTAssertTrue(omitted.allSatisfy { $0.provenance == nil })
    }

    func testProjectionAddsMarkedRecordThroughSharedSetWithoutDisturbingRealRecords() throws {
        let source = [real("_OBJC_IVAR_$_A.x", at: 0x5000), real("_f", at: 0x1000)]
        let classes = [cls("A", ivars: [("x", 0x5000), ("y", 0x5008)])]
        let records = try Builder.projectSymbols(
            source, functions: [], imageID: imageID, objcClasses: classes, mappedLayout: try layout())
        XCTAssertEqual(records.map(\.name), ["_f", "_OBJC_IVAR_$_A.x", "_OBJC_IVAR_$_A.y"])
        XCTAssertEqual(records.map(\.provenance), [nil, nil, marker])
        let base = try Builder.projectSymbols(source, functions: [], imageID: imageID)
        XCTAssertEqual(records.filter { $0.provenance == nil }, base)
    }

    func testProjectedRecordsCountTowardTheUnchangedCeiling() throws {
        func filler(_ count: Int) -> [SymbolSummary] {
            (0..<count).map { real("s\($0)", at: 0x1_0000_0000 + UInt64($0) * 8) }
        }
        let classes = [cls("A", ivars: [("x", 0x5000)])]
        let accepted = try Builder.projectSymbols(
            filler(99_999), functions: [], imageID: imageID, objcClasses: classes, mappedLayout: try layout())
        XCTAssertEqual(accepted.count, 100_000)
        XCTAssertEqual(accepted.filter { $0.provenance != nil }.count, 1)
        XCTAssertThrowsError(try Builder.projectSymbols(
            filler(100_000), functions: [], imageID: imageID, objcClasses: classes, mappedLayout: try layout())
        ) { XCTAssertEqual($0 as? NativeDecompilerSnapshotProjectionError, .tooManySymbols) }
    }

    func testShippedBuildsKeepTheProjectionDisabled() {
        XCTAssertFalse(Builder.objCIvarMetadataProjectionEnabled)
    }
}
