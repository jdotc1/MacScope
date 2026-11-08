import Foundation
import XCTest
@testable import MacScope

/// T10; authored, unrun; guard; F1 plus F3 scalar stream. This covers the
/// persisted-value rehydrate seam, not an unprovided persistence codec roundtrip.
/// RULING 1284-UUID: compare all semantic fields after mapping fresh IDs;
/// every UUID already present in persisted input/overrides remains literal.
@MainActor
final class ReadyRehydrationParityTests: XCTestCase {
    override class func tearDown() {
        XCTAssertNoThrow(try ReadyCanonicalGoldens.finish(ReadyCanonicalGoldens.rehydrateIDs))
        super.tearDown()
    }
    func testPatchedDataGapAndRetainedStringSurviveRehydrate() throws {
        let fixture = TinyMachO.make(code: Data([
            0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00]))
        let url = try fixture.write()
        defer { try? FileManager.default.removeItem(at: url) }
        let engine = AnalysisEngine()
        let base = try engine.analyze(url: url, overrides: [
            fixture.baseAddress + 8: AddressOverride(isData: true),
            fixture.baseAddress + 12: AddressOverride(isData: true)])
        let store = WorkspaceStore(workspaceName: "rehydrate", snapshot: base, engine: engine)
        let patch = try XCTUnwrap(BytePatch.parse(hex: "1f 20 03 d5"))
        XCTAssertTrue(store.withSynchronousReanalysis {
            store.setPatch(fixture.baseAddress, in: base.primarySlot, patch)
        })
        var overrides = store.snapshot.primaryOverrides
        overrides[fixture.baseAddress + 8] = AddressOverride(isData: true)
        overrides[fixture.baseAddress + 12] = AddressOverride(isData: true)
        let analyzed = try engine.analyze(url: url, overrides: overrides)
        let prepared = try ReadyCanonicalGoldens.rehydrateInput(analyzed, sourceURL: url,
            literalAddress: fixture.baseAddress + 8)
        let persisted = prepared.persisted
        let literal = prepared.literal
        let expectedSections = prepared.expectedSections
        let expectedRanges = prepared.expectedRanges
        let result = try engine.rehydrate(imageBytes: analyzed.imageBytes,
            requestedSliceIndex: nil, preserving: persisted, overrides: overrides,
            cancellation: .never)
        let inputIDs = try AnalysisSnapshotCanonicalizer.inputUUIDs(in: (persisted, overrides))
        try ReadyCanonicalGoldens.image("rehydrate-patched-gap-string", current: result, input: persisted,
            sourceURL: url, inputUUIDs: inputIDs)
        XCTAssertEqual(result.analysisInputFingerprint?.overallSHA256,
                       persisted.analysisInputFingerprint?.overallSHA256)
        XCTAssertEqual(result.instructions, persisted.instructions)
        XCTAssertEqual(result.functions, persisted.functions)
        XCTAssertEqual(result.xrefs, persisted.xrefs)
        XCTAssertEqual(result.stringLiterals, [literal])
        XCTAssertEqual(result.imageBytes, analyzed.imageBytes)
        XCTAssertEqual(result.jumpTables, [:])
        XCTAssertFalse(result.sections.isEmpty)
        XCTAssertFalse(result.functions.contains { $0.startAddress == fixture.baseAddress + 8 })
        XCTAssertEqual(result.instructions.first?.bytes.split(separator: " ").compactMap { UInt8($0, radix: 16) }, [0x1f, 0x20, 0x03, 0xd5])
        var before = AnalysisSnapshotCanonicalizer()
        var after = AnalysisSnapshotCanonicalizer()
        try before.declareFresh(expectedSections.map(\.id), kind: "Section")
        try before.declareFresh(expectedRanges.map(\.id), kind: "CodeDataRange")
        try after.declareFresh(result.sections.map(\.id), kind: "Section")
        try after.declareFresh(result.codeDataRanges.map(\.id), kind: "CodeDataRange")
        XCTAssertEqual(try before.canonical(expectedSections, path: "$sections"),
                       try after.canonical(result.sections, path: "$sections"))
        XCTAssertEqual(try before.canonical(expectedRanges, path: "$ranges"),
                       try after.canonical(result.codeDataRanges, path: "$ranges"))
        XCTAssertEqual(result.relocations, persisted.relocations)
        XCTAssertEqual(result.objcSelectors, persisted.objcSelectors)
        XCTAssertEqual(result.diagnostics, analyzed.diagnostics)
    }

    /// F3 non-ARM-style widths, deliberately unsorted and unaligned. Index
    /// selection must preserve row order and use address membership, not stride.
    func testVariableWidthRowsUseHalfOpenMembership() {
        let addresses: [UInt64] = [0x1007, 0x1000, 0x1003, 0x1008]
        let widths = [1, 3, 4, 2]
        let rows = zip(addresses, widths).map { address, width in
            DecodedInstruction(address: address, bytes: Array(repeating: 0x90, count: width),
                mnemonic: "synthetic", operands: "", branchTarget: nil, comment: nil, flow: .return)
        }
        let ranges = (0..<9).map { _ in
            BinaryCodeDataRange(address: 0x1003, size: 4, kind: "data")
        }
        let index = CodeDataRangeIndex(ranges: ranges)
        let selected = rows.filter { index.contains(address: $0.address) }
        XCTAssertEqual(selected.map(\.address), [0x1003])
        XCTAssertEqual(rows.filter { !index.contains(address: $0.address) }.map(\.address),
                       [0x1007, 0x1000, 0x1008])
    }
}
