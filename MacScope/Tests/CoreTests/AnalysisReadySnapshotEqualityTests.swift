import Foundation
import XCTest
@testable import MacScope

// T1 complete semantic-document comparisons under RULING 1284-UUID. Authored, unrun.
// Input/stable UUIDs stay literal; confirmed fresh fields normalize, references included.
// Unknown UUID fields and opaque values remain fail-closed tripwires.
final class AnalysisReadySnapshotEqualityTests: XCTestCase {
    override class func tearDown() {
        XCTAssertNoThrow(try ReadyCanonicalGoldens.finish(ReadyCanonicalGoldens.analysisIDs))
        super.tearDown()
    }
    @MainActor
    func testGuardF1PatchedInputAgainstFrozenLegacy() throws {
        let fixture = TinyMachO.make(code: Data([0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]))
        let url = try fixture.write()
        defer { try? FileManager.default.removeItem(at: url) }
        let engine = AnalysisEngine()
        let initial = try engine.analyze(url: url)
        let store = WorkspaceStore(workspaceName: "ready-patch", snapshot: initial, engine: engine)
        let patch = try XCTUnwrap(BytePatch.parse(hex: "1f 20 03 d5"))
        let changed = store.withSynchronousReanalysis {
            store.setPatch(fixture.baseAddress, in: initial.primarySlot, patch)
        }
        XCTAssertTrue(changed)
        // Supplied synchronous scope completes reanalysis before reading authoring state.
        let overrides = store.snapshot.primaryOverrides
        XCTAssertNotNil(overrides[fixture.baseAddress]?.patch)
        let new = try engine.analyze(url: url, overrides: overrides)
        let again = try engine.analyze(url: url, overrides: overrides)
        try assertCanonical(new, again)
        try ReadyCanonicalGoldens.snapshot("f1-patched", current: new, sourceURL: url,
            inputUUIDs: AnalysisSnapshotCanonicalizer.inputUUIDs(in: overrides))
        XCTAssertEqual(new.instructions.first?.bytes.split(separator: " ").compactMap { UInt8($0, radix: 16) },
                       [0x1f, 0x20, 0x03, 0xd5])
    }

    @MainActor
    func testGuardF4JournalReplayAgainstFrozenLegacy() throws {
        let fixture = TinyMachO.make(code: Data([
            0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
            0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6]))
        let url = try fixture.write()
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: scratch) }
        let journal = scratch.appendingPathComponent("edits.journal")
        let engine = AnalysisEngine()
        let writer = WorkspaceStore(workspaceName: "ready-journal", snapshot: try engine.analyze(url: url), engine: engine)
        defer { writer.detachEditJournal()?.close() }
        let created = try writer.attachEditJournal(at: journal)
        XCTAssertTrue(created.created); XCTAssertEqual(created.replayed, 0)
        _ = try WorkspaceScriptingAPI(store: writer).execute("rename", arguments: .object([
            "address": .hex(fixture.baseAddress), "name": .string("replayed-entry")]))
        writer.detachEditJournal()?.close()
        let reader = WorkspaceStore(workspaceName: "ready-journal",
            snapshot: try engine.analyze(url: url), engine: engine)
        defer { reader.detachEditJournal()?.close() }
        let replayed = try reader.attachEditJournal(at: journal)
        XCTAssertEqual(replayed.replayed, 1)
        XCTAssertFalse(replayed.alreadyApplied)
        XCTAssertEqual(try WorkspaceScriptingAPI(store: reader).execute("name-at",
            arguments: .object(["address": .hex(fixture.baseAddress)])), .string("replayed-entry"))
        XCTAssertEqual(reader.snapshot.primaryOverrides, writer.snapshot.primaryOverrides)
        // attachEditJournal applies replay under withSynchronousReanalysis
        // (supplement WorkspaceStore:11331); both engines consume the replayed input.
        let overrides = reader.snapshot.primaryOverrides
        let new = try engine.analyze(url: url, overrides: overrides)
        let again = try engine.analyze(url: url, overrides: overrides)
        try assertCanonical(new, again)
        try ReadyCanonicalGoldens.snapshot("f4-journal", current: new, sourceURL: url,
            inputUUIDs: AnalysisSnapshotCanonicalizer.inputUUIDs(in: overrides))
    }

    private func assertCanonical(_ old: WorkspaceSnapshot, _ new: WorkspaceSnapshot) throws {
        XCTAssertFalse(new.instructions.isEmpty)
        XCTAssertEqual(old.instructions, new.instructions)
        XCTAssertEqual(old.functions, new.functions)
        XCTAssertEqual(old.symbols, new.symbols)
        XCTAssertEqual(old.jumpTables, new.jumpTables)
        XCTAssertEqual(try AnalysisSnapshotCanonicalizer.canonicalSnapshot(old),
                       try AnalysisSnapshotCanonicalizer.canonicalSnapshot(new))
    }
    func testGuardF1DataProcedureShapeAndHintMatrixAgainstFrozenLegacy() throws {
        let fixture = TinyMachO.make(code: Data([
            0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
            0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6]))
        let url = try fixture.write()
        defer { try? FileManager.default.removeItem(at: url) }
        let boundary = fixture.baseAddress + 12
        let overrides = [AddressOverride(isData: true), AddressOverride(markAsProcedure: true),
            AddressOverride(dataShape: DataShapeOverride(kind: .array, elementType: "int32_t", elementCount: 2))]
        for (index, value) in overrides.enumerated() {
            let b = try AnalysisEngine().analyze(url: url, overrides: [boundary: value])
            let c = try AnalysisEngine().analyze(url: url, overrides: [boundary: value])
            try assertCanonical(b, c)
            let id = ["f1-data", "f1-procedure", "f1-shape"][index]
            try ReadyCanonicalGoldens.snapshot(id, current: b, sourceURL: url,
                inputUUIDs: AnalysisSnapshotCanonicalizer.inputUUIDs(in: [boundary: value]))
            XCTAssertEqual(b.functions.contains { $0.startAddress == boundary }, index == 1)
        }
        let hinted = TinyMachO.make(code: Data([
            0x00, 0x00, 0x1f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
            0xf8, 0xff, 0xff, 0xff, 0xfc, 0xff, 0xff, 0xff]))
        let hintedURL = try hinted.write()
        defer { try? FileManager.default.removeItem(at: hintedURL) }
        let hint = SwitchHintOverride(tableBase: hinted.baseAddress + 12, entryCount: 2,
            entryStride: 4, isRelativeToBase: true)
        let values = [hinted.baseAddress: AddressOverride(switchHint: hint)]
        let b = try AnalysisEngine().analyze(url: hintedURL, overrides: values)
        let c = try AnalysisEngine().analyze(url: hintedURL, overrides: values)
        try assertCanonical(b, c)
        try ReadyCanonicalGoldens.snapshot("f1-hint", current: b, sourceURL: hintedURL,
            inputUUIDs: AnalysisSnapshotCanonicalizer.inputUUIDs(in: values))
        let edges = b.controlFlowEdges.filter { $0.kind == "switch" && $0.from == hinted.baseAddress }
        XCTAssertEqual(Set(edges.map(\.to)), [hinted.baseAddress + 4, hinted.baseAddress + 8])
    }
    private struct Row { var id: UUID; var name: String; var reference: UUID }
    private struct ReferenceDocument { var reference: UUID; var records: [XRef] }
    func testGuardFirstAppearanceIncludesReferencesBeforeDefinitions() throws {
        let a = UUID(), b = UUID(), x = UUID(), y = UUID()
        let left = ReferenceDocument(reference: b, records: [
            XRef(id: a, from: 1, to: 2, kind: "call"), XRef(id: b, from: 3, to: 4, kind: "call")])
        var right = ReferenceDocument(reference: y, records: [
            XRef(id: x, from: 1, to: 2, kind: "call"), XRef(id: y, from: 3, to: 4, kind: "call")])
        let canonical = try AnalysisSnapshotCanonicalizer.canonicalDocument(left)
        XCTAssertEqual(canonical, try AnalysisSnapshotCanonicalizer.canonicalDocument(right))
        right.reference = x
        XCTAssertNotEqual(canonical, try AnalysisSnapshotCanonicalizer.canonicalDocument(right))
        right.reference = UUID()
        XCTAssertThrowsError(try AnalysisSnapshotCanonicalizer.canonicalDocument(right)) {
            XCTAssertEqual($0 as? AnalysisSnapshotCanonicalizer.Failure, .undeclaredUUID("$root.reference"))
        }
    }
    func testGuardRemapsReferencesPreservesOrderAndStableIDs() throws {
        let a = UUID(), b = UUID(), x = UUID(), y = UUID(), stable = UUID()
        var left = AnalysisSnapshotCanonicalizer()
        var right = AnalysisSnapshotCanonicalizer()
        try left.declareFresh([a, b], kind: "XRef")
        try right.declareFresh([x, y], kind: "XRef")
        try left.declareStable([stable]); try right.declareStable([stable])
        let lhs = [Row(id: a, name: "first", reference: b),
                   Row(id: b, name: "second", reference: stable)]
        var rhs = [Row(id: x, name: "first", reference: y),
                   Row(id: y, name: "second", reference: stable)]
        XCTAssertEqual(try left.canonical(lhs), try right.canonical(rhs))
        rhs[0].reference = x
        XCTAssertNotEqual(try left.canonical(lhs), try right.canonical(rhs))
        rhs[0].reference = y; rhs[0].name = "changed"
        XCTAssertNotEqual(try left.canonical(lhs), try right.canonical(rhs))
        rhs[0].name = "first"; rhs.reverse()
        XCTAssertNotEqual(try left.canonical(lhs), try right.canonical(rhs))
        let differentStable = UUID()
        try right.declareStable([differentStable])
        XCTAssertNotEqual(try left.canonical(stable), try right.canonical(differentStable))
    }
    func testGuardUndeclaredUUIDFailsAtExactFieldPath() throws {
        let declared = UUID(), unknown = UUID()
        var comparator = AnalysisSnapshotCanonicalizer()
        try comparator.declareFresh([declared], kind: "XRef")
        XCTAssertThrowsError(try comparator.canonical(Row(id: declared, name: "x", reference: unknown))) {
            XCTAssertEqual($0 as? AnalysisSnapshotCanonicalizer.Failure,
                           .undeclaredUUID("$root.reference"))
        }
    }
    func testGuardDictionaryAndSetOrderAreNotArrayOrder() throws {
        let c = AnalysisSnapshotCanonicalizer()
        XCTAssertEqual(try c.canonical(Set([1, 2, 3])), try c.canonical(Set([3, 2, 1])))
        XCTAssertEqual(try c.canonical([1: "one", 2: "two"]),
                       try c.canonical([2: "two", 1: "one"]))
        XCTAssertNotEqual(try c.canonical([1, 2]), try c.canonical([2, 1]))
    }
    func testGuardActualSnapshotEqualityDetectsSemanticMutation() throws {
        let rows = ReadyFixture.instructions(count: 2)
        let snapshot = try AnalysisEngine(loader: ReadyFixture.Loader(binary:
            ReadyFixture.binary(instructions: rows)), decoder: ReadyFixture.Decoder(rows: rows))
            .analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        XCTAssertFalse(snapshot.functions.isEmpty)
        let before = try AnalysisSnapshotCanonicalizer.canonicalSnapshot(snapshot)
        var mutated = snapshot
        mutated.sourceLinkState = Data([1, 2, 3])
        XCTAssertNotEqual(before, try AnalysisSnapshotCanonicalizer.canonicalSnapshot(mutated))
    }
    func testGuardSuppliedInputUUIDReplacementCannotNormalizeAway() throws {
        let supplied = UUID()
        var input = ImageAnalysis()
        input.stringLiterals = [StringLiteralSummary(id: supplied, value: "text", address: 0x1000,
            sourceSection: ".text", byteLength: 4)]
        let ids = try AnalysisSnapshotCanonicalizer.inputUUIDs(in: input)
        XCTAssertTrue(ids.contains(supplied))
        var changed = input
        changed.stringLiterals = [StringLiteralSummary(id: UUID(), value: "text", address: 0x1000,
            sourceSection: ".text", byteLength: 4)]
        XCTAssertNotEqual(try AnalysisSnapshotCanonicalizer.canonicalImage(input, inputUUIDs: ids),
                          try AnalysisSnapshotCanonicalizer.canonicalImage(changed, inputUUIDs: ids))
    }
    func testGuardCatalogMintIDsNormalizeButInputIDsAndRevisionDoNot() throws {
        let first = DebuggerLogicalBreakpointCatalog.freshPristine()
        let second = DebuggerLogicalBreakpointCatalog.freshPristine()
        XCTAssertEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(first),
                       try AnalysisSnapshotCanonicalizer.canonicalDocument(second))
        let inputIDs = try AnalysisSnapshotCanonicalizer.inputUUIDs(in: first)
        XCTAssertNotEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(first, inputUUIDs: inputIDs),
                          try AnalysisSnapshotCanonicalizer.canonicalDocument(second, inputUUIDs: inputIDs))
        let changed = try DebuggerLogicalBreakpointCatalog(catalogID: first.catalogID, revision: 2, specifications: [])
        XCTAssertNotEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(first, inputUUIDs: inputIDs),
                          try AnalysisSnapshotCanonicalizer.canonicalDocument(changed, inputUUIDs: inputIDs))
        XCTAssertEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(DebuggerLaunchProfileCatalog.freshPristine()),
                       try AnalysisSnapshotCanonicalizer.canonicalDocument(DebuggerLaunchProfileCatalog.freshPristine()))
    }
    func testGuardStoredFingerprintIsValidatedBeforePinning() throws {
        let rows = ReadyFixture.instructions(count: 2)
        var snapshot = try AnalysisEngine(loader: ReadyFixture.Loader(binary: ReadyFixture.binary(instructions: rows)),
            decoder: ReadyFixture.Decoder(rows: rows)).analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        let binary = try XCTUnwrap(snapshot.binaries.first)
        var differentInput = try XCTUnwrap(snapshot.analysisBySlot[binary.slot])
        differentInput.imageBytes.append(0)
        snapshot.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: differentInput)
        XCTAssertThrowsError(try AnalysisSnapshotCanonicalizer.canonicalSnapshot(snapshot)) {
            XCTAssertEqual($0 as? AnalysisSnapshotCanonicalizer.Failure,
                           .fingerprintMismatch("analysisBySlot.analysisInputFingerprint"))
        }
    }
    func testGuardF3VariableWidthListingIsNotFixedWidth() throws {
        var rows = ReadyFixture.instructions(count: 4)
        let addresses: [UInt64] = [0x1000, 0x1001, 0x1003, 0x1006]
        let widths = [1, 2, 3, 5]
        for i in rows.indices { rows[i].address = addresses[i]; rows[i].bytes = Array(repeating: 0x90, count: widths[i]) }
        for count in [0, 1, 8, 9] {
            let ranges = (0..<count).map { BinaryCodeDataRange(address: 0x1003, size: 3, kind: "range\($0)") }
            var binary = ReadyFixture.binary(instructions: rows, ranges: ranges)
            binary.cpuType = MachOConstants.cpuTypeX86_64
            binary.functionStarts = [0x1000, 0x1003]
            let snapshot = try AnalysisEngine(loader: ReadyFixture.Loader(binary: binary),
                decoder: ReadyFixture.Decoder(rows: rows)).analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
            XCTAssertEqual(snapshot.instructions.map(\.address), addresses)
            XCTAssertEqual(snapshot.instructions.map(\.byteWidth), [1, 2, 3, 5])
            XCTAssertEqual(snapshot.functions.map(\.startAddress), count == 0 ? [0x1000, 0x1003] : [0x1000])
            XCTAssertEqual(snapshot.codeDataRanges.map(\.address), ranges.map(\.address))
            XCTAssertEqual(snapshot.codeDataRanges.map(\.size), ranges.map(\.size))
            XCTAssertEqual(snapshot.codeDataRanges.map(\.kind), ranges.map(\.kind))
            let again = try AnalysisEngine(loader: ReadyFixture.Loader(binary: binary),
                decoder: ReadyFixture.Decoder(rows: rows)).analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
            try assertCanonical(snapshot, again)
            try ReadyCanonicalGoldens.snapshot("f3-ranges-\(count)", current: snapshot)
        }
    }
    func testGuardExistingX86DecoderStreamThroughAnalysis() throws {
        // Existing supplement X86DisassemblyTests:221-228; not an assembled binary.
        let bytes: [UInt8] = [0x48, 0x6b, 0xc7, 0x18, 0x48, 0x89, 0xc1, 0xc3]
        var binary = ReadyFixture.binary(instructions: ReadyFixture.instructions(count: 2))
        binary.bytes = Data(bytes)
        binary.cpuType = MachOConstants.cpuTypeX86_64
        let new = try AnalysisEngine(loader: ReadyFixture.Loader(binary: binary), decoder: X86_64Decoder())
            .analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        let again = try AnalysisEngine(loader: ReadyFixture.Loader(binary: binary), decoder: X86_64Decoder())
            .analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        XCTAssertEqual(new.instructions.map(\.mnemonic), ["imul", "mov", "ret"])
        XCTAssertEqual(new.instructions.map(\.address), [0x1000, 0x1004, 0x1007])
        XCTAssertEqual(new.instructions.map(\.byteWidth), [4, 3, 1])
        try assertCanonical(new, again)
        try ReadyCanonicalGoldens.snapshot("x86-stream", current: new)
    }
    func testGuardF1OrdinaryAndTruncatedHaveNonemptyListings() throws {
        for code in [Data([0xc0, 0x03, 0x5f, 0xd6]), Data([0xc0, 0x03, 0x5f, 0xd6, 0xff])] {
            let url = try TinyMachO.make(code: code).write()
            defer { try? FileManager.default.removeItem(at: url) }
            let first = try AnalysisEngine().analyze(url: url)
            let second = try AnalysisEngine().analyze(url: url)
            try assertCanonical(first, second)
            let id = code.count == 4 ? "f1-ordinary" : "f1-truncated"
            try ReadyCanonicalGoldens.snapshot(id, current: first, sourceURL: url)
            XCTAssertFalse(first.instructions.isEmpty)
            XCTAssertEqual(first.instructions, second.instructions)
            XCTAssertEqual(first.functions, second.functions)
            XCTAssertEqual(first.symbols, second.symbols)
            let binary = try XCTUnwrap(first.binaries.first)
            let analysis = try XCTUnwrap(first.analysisBySlot[binary.slot])
            let stored = try XCTUnwrap(analysis.analysisInputFingerprint)
            let rebuilt = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
            XCTAssertEqual(stored.overallSHA256, rebuilt.overallSHA256)
            // Above compares full canonical documents; this also checks the original same-run digest.
        }
    }
    func testGuardF5BothUniversalSelectionsRunToNonemptyListing() throws {
        let fixture = MachOFixture.makeUniversalDualExecutable()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fixture.bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        for selection in [0, 1] {
            let a = try AnalysisEngine().analyze(url: url, requestedSliceIndex: selection)
            let b = try AnalysisEngine().analyze(url: url, requestedSliceIndex: selection)
            try assertCanonical(a, b)
            try ReadyCanonicalGoldens.snapshot("f5-slice-\(selection)", current: a, sourceURL: url)
            XCTAssertEqual(a.binaries.first?.selectedSliceIndex, selection)
            XCTAssertFalse(a.instructions.isEmpty)
            XCTAssertEqual(a.instructions, b.instructions)
            XCTAssertEqual(a.functions, b.functions)
            // F5 slice 0 contains arm64 fixture bytes under an x86 header, not genuine
            // multi-instruction x86 code; no genuine-x86 binary is invented.
        }
    }
}
