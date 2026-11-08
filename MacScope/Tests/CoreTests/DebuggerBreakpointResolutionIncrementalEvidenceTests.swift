import Foundation
import XCTest
@testable import MacScope

@MainActor
final class DebuggerBreakpointResolutionIncrementalEvidenceTests: XCTestCase {
    private let address: UInt64 = 0x1_0000_1000
    private let siblingAddress: UInt64 = 0x1_0000_2000
    private let primaryID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    private let siblingID = UUID(uuidString: "20000000-0000-0000-0000-000000000002")!
    private let catalogID = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    private let workspaceID = UUID(uuidString: "40000000-0000-0000-0000-000000000004")!
    private let siblingSlot = ImageSlot(rawValue: 7)
    private typealias Statistics = DebuggerBreakpointResolutionEvidenceStatistics

    @MainActor
    private struct Pair {
        var snapshot: WorkspaceSnapshot
        var artifacts: DebuggerWorkspaceArtifactCatalogLedger
        var incremental: DebuggerBreakpointResolutionCatalogLedger
        var full: DebuggerBreakpointResolutionCatalogLedger
        let workspaceID: UUID

        init(snapshot: WorkspaceSnapshot, workspaceID: UUID) {
            self.snapshot = snapshot
            self.workspaceID = workspaceID
            let artifacts = DebuggerWorkspaceArtifactCatalogLedger(snapshot: snapshot)
            self.artifacts = artifacts
            self.incremental = DebuggerBreakpointResolutionCatalogLedger(
                snapshot: snapshot, workspaceID: workspaceID, artifactCatalog: artifacts.catalog)
            self.full = DebuggerBreakpointResolutionCatalogLedger(
                snapshot: snapshot, workspaceID: workspaceID, artifactCatalog: artifacts.catalog,
                incrementalEvidence: false)
            assertEqual()
        }

        func assertEqual(file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertEqual(incremental.catalog, full.catalog, file: file, line: line)
            XCTAssertTrue(full.exactDigestsForTesting.isEmpty, file: file, line: line)
            XCTAssertEqual(Set(incremental.exactDigestsForTesting.keys),
                           Set(incremental.catalog.owners.map { $0.coordinate.binaryID }), file: file, line: line)
            for owner in incremental.catalog.owners {
                let bytes = DebuggerBreakpointResolutionCatalogLedger.exactDigest(of: owner)
                XCTAssertEqual(incremental.exactDigestsForTesting[owner.coordinate.binaryID],
                               bytes, file: file, line: line)
                let reference = full.catalog.owners.first { $0.coordinate.binaryID == owner.coordinate.binaryID }
                XCTAssertNotNil(reference, file: file, line: line)
                if let reference {
                    XCTAssertEqual(bytes, DebuggerBreakpointResolutionCatalogLedger.exactDigest(of: reference),
                                   file: file, line: line)
                }
            }
        }

        mutating func advance(_ expected: Statistics? = nil, replacement: Bool = false,
                              file: StaticString = #filePath, line: UInt = #line) {
            let before = incremental.evidenceStatisticsForTesting
            let artifactCatalog = artifacts.reconcile(snapshot: snapshot, fullWorkspaceReplacement: replacement)
            let left = incremental.reconcile(snapshot: snapshot, workspaceID: workspaceID,
                artifactCatalog: artifactCatalog, fullWorkspaceReplacement: replacement)
            let right = full.reconcile(snapshot: snapshot, workspaceID: workspaceID,
                artifactCatalog: artifactCatalog, fullWorkspaceReplacement: replacement)
            XCTAssertEqual(left, right, file: file, line: line)
            assertEqual(file: file, line: line)
            if let expected {
                let after = incremental.evidenceStatisticsForTesting
                let delta = Statistics(fullOwnerBuilds: after.fullOwnerBuilds - before.fullOwnerBuilds,
                    slicedOwners: after.slicedOwners - before.slicedOwners,
                    reusedOwners: after.reusedOwners - before.reusedOwners,
                    slicedAddresses: after.slicedAddresses - before.slicedAddresses)
                XCTAssertEqual(delta, expected, file: file, line: line)
            }
        }
    }

    private func pair(extended: Bool = true) -> Pair {
        Pair(snapshot: snapshot(extended: extended), workspaceID: workspaceID)
    }

    private func snapshot(extended: Bool) -> WorkspaceSnapshot {
        var primary = resolutionAnalysis(address: address, extended: extended)
        primary.sourceLines = [exactSourceLine(address: address)]
        return WorkspaceSnapshot(
            binaries: [verifiedBinary(id: primaryID, slot: .primary, shaByte: "a", extended: extended),
                       verifiedBinary(id: siblingID, slot: siblingSlot, shaByte: "b")],
            analysisBySlot: [.primary: primary, siblingSlot: resolutionAnalysis(address: siblingAddress)],
            logicalBreakpointCatalog: .freshPristine(catalogID: catalogID))
    }

    private func makeResolutionStore() -> WorkspaceStore {
        WorkspaceStore(workspaceName: "Resolution catalog", snapshot: snapshot(extended: false),
                       engine: AnalysisEngine(), autosaveScheduler: nil, workspaceID: workspaceID,
                       logicalBreakpointCatalogAvailability: .available)
    }

    private func verifiedBinary(id: UUID, slot: ImageSlot, shaByte: String,
                                extended: Bool = false) -> BinaryImage {
        let identity = try! MachOSliceArtifactIdentity(
            uuid: id, rawCPUType: MachOConstants.cpuTypeARM64, rawCPUSubtype: 0,
            selectedSliceSHA256: String(repeating: shaByte, count: 64), selectedSliceByteCount: 0x4000)
        var records: [MachOPreferredSegmentLayout.Record] = [
            .init(name: "__TEXT", preferredVMStart: slot == .primary ? address : siblingAddress,
                  preferredVMSize: 0x1000, sliceRelativeFileOffset: 0, fileSize: 0x1000, initialProtections: 5)
        ]
        if extended && slot == .primary {
            records.append(.init(name: "__DATA", preferredVMStart: address + 0x1000,
                preferredVMSize: 0x1000, sliceRelativeFileOffset: 0x1000,
                fileSize: 0x1000, initialProtections: 3))
        }
        let layout = try! MachOPreferredSegmentLayout(records: records,
            selectedSliceByteCount: identity.selectedSliceByteCount)
        return BinaryImage(id: id, name: "image-\(slot.rawValue)", path: "/tmp/image-\(slot.rawValue)",
            kind: "Mach-O executable", architecture: "arm64", artifactIdentity: identity,
            preferredSegmentLayout: layout, artifactIntegrityState: .verified, slot: slot)
    }

    private func resolutionAnalysis(address: UInt64, extended: Bool = false) -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.sections = [SectionSummary(id: UUID(), name: "__TEXT", address: address,
            size: 0x1000, fileOffset: 0, isExecutable: true)]
        analysis.instructions = [instruction(address)]
        if extended {
            analysis.instructions.append(instruction(address + 4))
            analysis.instructions.append(instruction(address + 0x1000))
        }
        analysis.functions = [function(address)]
        analysis.symbols = [symbol(address, raw: "_entry")]
        return analysis
    }

    private func function(_ start: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: "entry", startAddress: start, endAddress: start + 4, confidence: 1)
    }

    private func symbol(_ start: UInt64?, raw: String?) -> SymbolSummary {
        SymbolSummary(id: UUID(), name: "entry", address: start, kind: "function",
                      libraryName: nil, rawLinkageName: raw)
    }

    private func instruction(_ address: UInt64, hasBreakpoint: Bool = false) -> InstructionRow {
        InstructionRow(address: address, bytes: "1f 20 03 d5", mnemonic: "nop", operands: "",
                       hasBreakpoint: hasBreakpoint, comment: nil)
    }

    private func exactSourceLine(address: UInt64) -> SourceLineEntry {
        SourceLineEntry(address: address, file: "/src/main.c", line: 17, column: 3, endSequence: false,
            debugArtifactUUID: UUID(uuidString: "60000000-0000-0000-0000-000000000006"),
            debugArtifactMachOSHA256: String(repeating: "d", count: 64),
            debugArtifactMachOByteCount: 0x2000, lineProgramUnitOffset: 0x40,
            fileTableIndex: 2, tablePath: .absoluteUTF8("/src/main.c"))
    }

    private func dataOverride() -> AddressOverride {
        var value = AddressOverride()
        value.isData = true
        return value
    }

    private func names(keeping previous: [ImageAddress: AddressOverride] = [:]) -> [ImageAddress: AddressOverride] {
        var result = previous
        for index in 0..<50 {
            let key = ImageAddress(slot: .primary, address: address + UInt64(index * 4))
            var value = result[key] ?? AddressOverride()
            value.customName = "name\(index)"
            result[key] = value
        }
        return result
    }

    private func owner(_ catalog: DebuggerBreakpointResolutionCatalog, _ id: UUID) throws
        -> DebuggerBreakpointResolutionOwnerIndex {
        try XCTUnwrap(catalog.owners.first { $0.coordinate.binaryID == id })
    }

    private func assertPrimaryAdvanced(_ before: DebuggerBreakpointResolutionCatalog,
                                       _ after: DebuggerBreakpointResolutionCatalog,
                                       file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try owner(after, primaryID).revision, try owner(before, primaryID).revision + 1,
                       file: file, line: line)
        XCTAssertEqual(try owner(after, siblingID).revision, try owner(before, siblingID).revision,
                       file: file, line: line)
    }

    func testF1RenameReusesBothOwners() {
        var value = pair()
        let before = value.incremental.catalog
        var edit = AddressOverride()
        edit.customName = "renamed"
        value.snapshot.addressOverrides[ImageAddress(slot: .primary, address: address)] = edit
        value.advance(.init(reusedOwners: 2))
        XCTAssertEqual(value.incremental.catalog, before)
    }

    func testF2NamesOnlyBatchFilterAndMergeBothReuse() {
        var value = pair()
        let before = value.incremental.catalog
        value.snapshot.addressOverrides = value.snapshot.addressOverrides.filter { $0.key.slot != .primary }
        value.advance(.init(reusedOwners: 2))
        value.snapshot.addressOverrides.merge(names()) { _, new in new }
        value.advance(.init(reusedOwners: 2))
        XCTAssertEqual(value.incremental.catalog, before)
    }

    func testF3ExecutableDataSliceChangesExactlyOneKindByte() throws {
        var value = pair()
        let before = value.incremental.catalog
        let beforeBytes = try XCTUnwrap(value.incremental.exactDigestsForTesting[primaryID])
        value.snapshot.addressOverrides[ImageAddress(slot: .primary, address: address + 4)] = dataOverride()
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        try assertPrimaryAdvanced(before, value.incremental.catalog)
        let afterBytes = try XCTUnwrap(value.incremental.exactDigestsForTesting[primaryID])
        XCTAssertEqual(beforeBytes.count, 401)
        XCTAssertEqual(afterBytes.count, 401)
        XCTAssertEqual(beforeBytes.indices.filter { beforeBytes[$0] != afterBytes[$0] }, [123])
        XCTAssertEqual(beforeBytes[123], 0)
        XCTAssertEqual(afterBytes[123], 1)
        let primary = try owner(value.incremental.catalog, primaryID)
        XCTAssertEqual(primary.staticAddresses.first { $0.preferredVA == address + 4 }?.kind, .data)
    }

    func testF4BatchWithDataOverrideSlicesOnFilterAndMerge() throws {
        var value = pair()
        let key = ImageAddress(slot: .primary, address: address + 4)
        value.snapshot.addressOverrides[key] = dataOverride()
        value.advance()
        let withData = value.incremental.catalog
        let merged = names(keeping: value.snapshot.addressOverrides)
        value.snapshot.addressOverrides = value.snapshot.addressOverrides.filter { $0.key.slot != .primary }
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        try assertPrimaryAdvanced(withData, value.incremental.catalog)
        let filtered = value.incremental.catalog
        value.snapshot.addressOverrides.merge(merged) { _, new in new }
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        try assertPrimaryAdvanced(filtered, value.incremental.catalog)
    }

    func testF5MakeCodeAndItsUndoEachSlice() throws {
        var value = pair()
        let key = ImageAddress(slot: .primary, address: address + 4)
        value.snapshot.addressOverrides[key] = dataOverride()
        value.advance()
        var before = value.incremental.catalog
        var code = dataOverride()
        code.isData = false
        value.snapshot.addressOverrides[key] = code
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        try assertPrimaryAdvanced(before, value.incremental.catalog)
        before = value.incremental.catalog
        value.snapshot.addressOverrides[key] = dataOverride()
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        try assertPrimaryAdvanced(before, value.incremental.catalog)
    }

    func testF6NonExecutableDataSliceKeepsCatalogAndAdvancesStoredOverrideSet() {
        var value = pair()
        let before = value.incremental.catalog
        let key = ImageAddress(slot: .primary, address: address + 0x1000)
        value.snapshot.addressOverrides[key] = dataOverride()
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        XCTAssertEqual(value.incremental.catalog, before)
        value.advance(.init(reusedOwners: 2))
        value.snapshot.addressOverrides[key] = nil
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        XCTAssertEqual(value.incremental.catalog, before)
    }

    func testF7OverrideAtNonStaticAddressIsStoredWithoutABytePatch() {
        var value = pair()
        let before = value.incremental.catalog
        value.snapshot.addressOverrides[ImageAddress(slot: .primary, address: address + 8)] = dataOverride()
        value.advance(.init(slicedOwners: 1, reusedOwners: 1))
        XCTAssertEqual(value.incremental.catalog, before)
        value.advance(.init(reusedOwners: 2))
    }

    func testF7DegenerateDataShapeReusesAndUndefinedSlices() throws {
        var degenerate = pair()
        let before = degenerate.incremental.catalog
        var shape = AddressOverride()
        shape.dataShape = DataShapeOverride(kind: .array, elementCount: 0)
        XCTAssertTrue(shape.dataShape?.isEmpty == true)
        degenerate.snapshot.addressOverrides[ImageAddress(slot: .primary, address: address + 4)] = shape
        degenerate.advance(.init(reusedOwners: 2))
        XCTAssertEqual(degenerate.incremental.catalog, before)

        var undefined = pair()
        let old = undefined.incremental.catalog
        var edit = AddressOverride()
        edit.isUndefined = true
        undefined.snapshot.addressOverrides[ImageAddress(slot: .primary, address: address + 4)] = edit
        undefined.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        try assertPrimaryAdvanced(old, undefined.incremental.catalog)
        XCTAssertEqual(try owner(undefined.incremental.catalog, primaryID).staticAddresses
            .first { $0.preferredVA == address + 4 }?.kind, .data)
    }

    func testF8EachAnalysisArrayChangeRebuildsOnlyPrimaryIncludingDuplicateVA() {
        let changes: [(inout ImageAnalysis) -> Void] = [
            { $0.instructions.append(self.instruction(self.address + 4)) }, // Intentional duplicate VA.
            { $0.symbols[0].rawLinkageName = "_different" },
            { $0.functions.append(self.function(self.address + 8)) },
            { $0.sourceLines.append(self.exactSourceLine(address: self.address + 4)) }
        ]
        for change in changes {
            var value = pair()
            value.snapshot.mutateAnalysis(in: .primary, change)
            value.advance(.init(fullOwnerBuilds: 1, reusedOwners: 1))
        }
    }

    func testF9OwnerReplacementRemovalAndFullReplacement() {
        var replaced = pair()
        let newID = UUID(uuidString: "50000000-0000-0000-0000-000000000005")!
        replaced.snapshot.binaries[1] = verifiedBinary(id: newID, slot: siblingSlot, shaByte: "b")
        replaced.advance(.init(fullOwnerBuilds: 1, reusedOwners: 1))
        XCTAssertNil(replaced.incremental.exactDigestsForTesting[siblingID])
        XCTAssertNotNil(replaced.incremental.exactDigestsForTesting[newID])

        var removed = pair()
        removed.snapshot.binaries.removeAll { $0.id == siblingID }
        removed.advance(.init(reusedOwners: 1))
        XCTAssertEqual(Set(removed.incremental.exactDigestsForTesting.keys), [primaryID])

        var all = pair()
        all.advance(.init(fullOwnerBuilds: 2), replacement: true)
    }

    func testF10SymbolGroupingMatchesFourLiteralFunctionExpectationsAtInit() throws {
        var input = snapshot(extended: true)
        input.mutateAnalysis(in: .primary) { analysis in
            analysis.functions = [function(address), function(address + 4), function(address + 8), function(address + 12)]
            analysis.symbols = [
                symbol(address, raw: "_left"), symbol(address, raw: "_right"),
                symbol(address + 4, raw: "_same"), symbol(address + 4, raw: "_same"),
                symbol(address + 8, raw: nil)
            ]
        }
        let value = Pair(snapshot: input, workspaceID: workspaceID)
        XCTAssertEqual(value.incremental.evidenceStatisticsForTesting, .init(fullOwnerBuilds: 2))
        let expected: [DebuggerBreakpointFunctionEvidence] = [
            .init(entryPreferredVA: address, rawLinkageName: nil),
            .init(entryPreferredVA: address + 4, rawLinkageName: "_same"),
            .init(entryPreferredVA: address + 8, rawLinkageName: nil),
            .init(entryPreferredVA: address + 12, rawLinkageName: nil)
        ]
        XCTAssertEqual(try owner(value.incremental.catalog, primaryID).functions, expected)
        XCTAssertEqual(try owner(value.full.catalog, primaryID).functions, expected)
    }


    private func assertStoreEqualsFreshFull(_ store: WorkspaceStore,
                                           file: StaticString = #filePath, line: UInt = #line) {
        let reference = DebuggerBreakpointResolutionCatalogLedger(snapshot: store.snapshot,
            workspaceID: store.workspaceID, artifactCatalog: store.debuggerWorkspaceArtifactCatalog,
            incrementalEvidence: false).catalog
        let actual = store.debuggerBreakpointResolutionCatalog
        XCTAssertEqual(Set(actual.owners.map(\.coordinate)), Set(reference.owners.map(\.coordinate)),
                       file: file, line: line)
        let actualBytes = Dictionary(uniqueKeysWithValues: actual.owners.map {
            ($0.coordinate, DebuggerBreakpointResolutionCatalogLedger.exactDigest(of: $0))
        })
        let referenceBytes = Dictionary(uniqueKeysWithValues: reference.owners.map {
            ($0.coordinate, DebuggerBreakpointResolutionCatalogLedger.exactDigest(of: $0))
        })
        XCTAssertEqual(actualBytes, referenceBytes, file: file, line: line)
    }

    func testF11StoreRenameBatchUndoAndDirectDataPublication() throws {
        let store = makeResolutionStore()
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertEqual(store.breakpointResolutionEvidenceStatisticsForTesting.fullOwnerBuilds, 2)
        assertStoreEqualsFreshFull(store)
        let original = store.debuggerBreakpointResolutionCatalog

        func checkAnnotation(_ action: () throws -> Void,
                             file: StaticString = #filePath, line: UInt = #line) rethrows {
            let before = store.breakpointResolutionEvidenceStatisticsForTesting
            try action()
            let after = store.breakpointResolutionEvidenceStatisticsForTesting
            XCTAssertEqual(after.fullOwnerBuilds - before.fullOwnerBuilds, 0, file: file, line: line)
            XCTAssertEqual(after.slicedOwners - before.slicedOwners, 0, file: file, line: line)
            XCTAssertEqual(store.debuggerBreakpointResolutionCatalog, original, file: file, line: line)
            assertStoreEqualsFreshFull(store, file: file, line: line)
        }
        checkAnnotation { store.setCustomName(address, in: .primary, name: "single") }
        let entries: [(address: UInt64, name: String?)] = (0..<50).map {
            (address + UInt64($0 * 4), "batch\($0)")
        }
        checkAnnotation { _ = store.setCustomNames(entries, in: .primary) }
        try checkAnnotation { _ = try api.execute("undo-last") }

        let before = store.breakpointResolutionEvidenceStatisticsForTesting
        var edited = store.snapshot
        let key = ImageAddress(slot: .primary, address: address)
        var value = edited.addressOverrides[key] ?? AddressOverride()
        value.isData = true
        edited.addressOverrides[key] = value
        store.snapshot = edited
        let after = store.breakpointResolutionEvidenceStatisticsForTesting
        XCTAssertEqual(after.fullOwnerBuilds - before.fullOwnerBuilds, 0)
        XCTAssertEqual(after.slicedOwners - before.slicedOwners, 1)
        assertStoreEqualsFreshFull(store)
    }

    func testF12StoreMakeDataAwaitsReanalysisBeforeComparingEvidence() async throws {
        let store = makeResolutionStore()
        let before = store.breakpointResolutionEvidenceStatisticsForTesting
        _ = try WorkspaceScriptingAPI(store: store).execute("make-data",
            arguments: .object(["address": .hex(address), "isData": .bool(true)]),
            forcesSynchronousReanalysis: false)
        await store.awaitPendingReanalysis()
        assertStoreEqualsFreshFull(store)
        XCTAssertGreaterThanOrEqual(store.breakpointResolutionEvidenceStatisticsForTesting.slicedOwners
                                    - before.slicedOwners, 1)
    }

    func testF13CanonicalEquivalentRawNameStillRebuildsForDifferentUTF8() throws {
        let decomposed = "_e\u{301}"
        let composed = "_\u{e9}"
        XCTAssertEqual(decomposed, composed)
        XCTAssertNotEqual(Data(decomposed.utf8), Data(composed.utf8))
        var input = snapshot(extended: true)
        input.mutateAnalysis(in: .primary) { $0.symbols[0].rawLinkageName = decomposed }
        var value = Pair(snapshot: input, workspaceID: workspaceID)
        let before = value.incremental.catalog
        let beforeBytes = try XCTUnwrap(value.incremental.exactDigestsForTesting[primaryID])
        value.snapshot.mutateAnalysis(in: .primary) { $0.symbols[0].rawLinkageName = composed }
        value.advance(.init(fullOwnerBuilds: 1, reusedOwners: 1))
        try assertPrimaryAdvanced(before, value.incremental.catalog)
        let afterBytes = try XCTUnwrap(value.incremental.exactDigestsForTesting[primaryID])
        XCTAssertNotEqual(beforeBytes, afterBytes)
        // Comparing only to the incremental owner's own digest would accept a stale owner.
        XCTAssertEqual(value.incremental.catalog, value.full.catalog)
        XCTAssertEqual(afterBytes, DebuggerBreakpointResolutionCatalogLedger.exactDigest(
            of: try owner(value.full.catalog, primaryID)))
    }

    func testDuplicateVARowsAreAllPatchedButCountAsOneSlicedAddress() throws {
        var input = snapshot(extended: true)
        input.mutateAnalysis(in: .primary) { $0.instructions.append(instruction(address + 4)) }
        var value = Pair(snapshot: input, workspaceID: workspaceID)
        value.snapshot.addressOverrides[ImageAddress(slot: .primary, address: address + 4)] = dataOverride()
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        let rows = try owner(value.incremental.catalog, primaryID).staticAddresses
            .filter { $0.preferredVA == address + 4 }
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.allSatisfy { $0.kind == .data })
    }

    func testNonemptyShapeAndUndefinedShareTheSameOverridePredicateSet() {
        var value = pair()
        let key = ImageAddress(slot: .primary, address: address + 4)
        var shape = AddressOverride()
        shape.dataShape = DataShapeOverride(kind: .array, elementCount: 1)
        XCTAssertFalse(shape.dataShape!.isEmpty)
        value.snapshot.addressOverrides[key] = shape
        value.advance(.init(slicedOwners: 1, reusedOwners: 1, slicedAddresses: 1))
        let before = value.incremental.catalog
        var undefined = AddressOverride()
        undefined.isUndefined = true
        value.snapshot.addressOverrides[key] = undefined
        value.advance(.init(reusedOwners: 2))
        XCTAssertEqual(value.incremental.catalog, before)
    }

    func testEvidenceNeutralKeyChangeIsStoredEvenWhenCatalogDoesNotAdvance() {
        var value = pair()
        let before = value.incremental.catalog
        value.snapshot.mutateAnalysis(in: .primary) { $0.instructions[0].comment = "ignored by evidence" }
        value.advance(.init(fullOwnerBuilds: 1, reusedOwners: 1))
        XCTAssertEqual(value.incremental.catalog, before)
        value.advance(.init(reusedOwners: 2))
    }
}
