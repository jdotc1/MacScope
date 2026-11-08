import XCTest
@testable import MacScope

/// HOP-5c follow-up: the once-per-image constant-string map (`ImageConstantStringProvider`).
/// A synthetic arm64 Mach-O with `__cstring`, `__ustring` and `__cfstring` drives the real
/// loader → engine → export path; the core `__cfstring` walk is also driven directly so the
/// chained-fixup decision is pinned without building an `LC_DYLD_CHAINED_FIXUPS` payload.
final class ImageConstantStringProviderTests: XCTestCase {
    // MARK: - __cfstring walk

    // Shared by the flat/page controls: three physical worlds collapse to the same map.
    // This invokes the actual core reader, not a fabricated CF map.
    static func storageAuthoritySnapshot(shared: Bool, utf16: Bool) -> WorkspaceSnapshot {
        precondition(!shared || !utf16)
        let cString: UInt64 = 0x2000, object: UInt64 = 0x4000
        let backing: UInt64 = shared ? cString : 0x8000
        var memory = SparseMemory()
        memory.put(cString, Array("txt".utf8) + [0])
        if !shared {
            memory.put(backing, utf16 ? [0x74, 0, 0x78, 0, 0x74, 0] : Array("txt".utf8))
        }
        memory.put(object, cfString(flags: utf16 ? 0x7D0 : 0x7C8, data: backing, length: 3))
        let objects = ImageConstantStringProvider.cfStrings(
            sections: [(object, 32)], pointerSize: 8, rebaseTargets: nil, read: memory.read)
        let literal = StringLiteralSummary(id: UUID(), value: "txt", address: cString,
            sourceSection: "__TEXT,__cstring", byteLength: 4)
        return WorkspaceSnapshot(binaries: [], functions: [FunctionSummary(id: UUID(), name: "reader",
            startAddress: 0x1000, endAddress: 0x1020, confidence: 1)],
            stringLiterals: [literal], stringLiteralCoverage: .complete, instructions: [],
            xrefs: [XRef(id: UUID(), from: 0x1000, to: cString, kind: XRefKind.string),
                    XRef(id: UUID(), from: 0x1004, to: object, kind: XRefKind.data)],
            hexBytes: Data(), constantStrings: ImageConstantStringProvider.build(
                stringLiterals: [literal], cfStrings: objects))
    }

    private func chainedXRefs(shared: Bool, table: ImageConstantStringProvider.CFStringBackingTable,
                              extraLiteral: UInt64? = nil, to target: UInt64) throws -> [ScriptValue] {
        var snapshot = Self.storageAuthoritySnapshot(shared: shared, utf16: false)
        snapshot.cfStringBackings = table
        if let extraLiteral {
            snapshot.stringLiterals.append(StringLiteralSummary(id: UUID(), value: "txt", address: extraLiteral,
                sourceSection: "__TEXT,__cstring", byteLength: 4))
        }
        return try XCTUnwrap(WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(target)]),
            snapshot: snapshot, checkpoint: {}).arrayValue)
    }

    func testE1EqualTextNeverLinksEvenWithATable() throws {
        let table = ImageConstantStringProvider.CFStringBackingTable(complete: true, backings: [0x4000: 0x8000])
        let rows = try chainedXRefs(shared: false, table: table, to: 0x2000)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?["from"], .hex(0x1000))
        XCTAssertEqual(rows.first?["kind"], .string("string"))
        XCTAssertNil(rows.first?["via"])
        XCTAssertNil(rows.first?["cfString"])
    }

    func testE2ChainedRowIsKeyedOnTheRetainedPointer() throws {
        let table = ImageConstantStringProvider.CFStringBackingTable(complete: true, backings: [0x4000: 0x8000])
        let rows = try chainedXRefs(shared: false, table: table, extraLiteral: 0x8000, to: 0x8000)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?["from"], .hex(0x1004))
        XCTAssertEqual(rows.first?["to"], .hex(0x8000))
        XCTAssertEqual(rows.first?["via"], .string("cfString"))
        XCTAssertEqual(rows.first?["cfString"], .hex(0x4000))
        XCTAssertEqual(rows.first?["kind"], .string("data"))
        XCTAssertEqual(rows.first?["cfStringStorage"], .object(["status": .string("retained")]))
    }

    func testE3SharedStorageLinksThroughThePointerNotTheText() throws {
        let table = ImageConstantStringProvider.CFStringBackingTable(complete: true, backings: [0x4000: 0x2000])
        let rows = try chainedXRefs(shared: true, table: table, to: 0x2000)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0]["from"], .hex(0x1000))
        XCTAssertNil(rows[0]["via"])
        XCTAssertEqual(rows[1]["from"], .hex(0x1004))
        XCTAssertEqual(rows[1]["via"], .string("cfString"))
        XCTAssertEqual(rows[1]["cfString"], .hex(0x4000))
    }

    @MainActor
    func testCoreReaderStorageWorldsDoNotAuthorizeLinks() throws {
        let expectedStorage: ScriptValue = .object([
            "status": .string("unavailable"), "reason": .string("backingAddressNotRetained")])
        let expectedMap: [UInt64: MacIRConstantString] = [
            0x2000: .init(text: "txt", kind: .cString), 0x4000: .init(text: "txt", kind: .cfString)]
        let coverages: [StringLiteralCoverage?] = [nil, .notAttempted, .complete,
            .incomplete(.stringCountLimitReached), .incomplete(.unterminatedField)]
        for (shared, utf16) in [(true, false), (false, false), (false, true)] {
            for coverage in coverages {
                var snapshot = Self.storageAuthoritySnapshot(shared: shared, utf16: utf16)
                snapshot.stringLiteralCoverage = coverage
                XCTAssertEqual(snapshot.constantStrings, expectedMap)
                let describer = try DataTargetDescriber(snapshot: snapshot, slot: snapshot.primarySlot,
                    targets: [0x4000], checkpoint: {})
                let fields = describer.describe(snapshot.xrefs[1], named: false)
                XCTAssertEqual(fields["targetKind"], .string("cfString"))
                XCTAssertEqual(fields["value"], .string("txt"))
                XCTAssertNil(fields["cString"])
                XCTAssertEqual(fields["cfStringStorage"], expectedStorage)
                let rows = try WorkspaceScriptingAPI.snapshotXRefRead(.object([
                    "to": .hex(0x2000)]), snapshot: snapshot, checkpoint: {}).arrayValue
                XCTAssertEqual(rows?.count, 1)
                XCTAssertEqual(rows?.first?["from"], .hex(0x1000))
                XCTAssertEqual(rows?.first?["to"], .hex(0x2000))
                XCTAssertEqual(rows?.first?["cfStringStorage"], expectedStorage)
                XCTAssertNil(rows?.first?["via"])
                XCTAssertNil(rows?.first?["cString"])
            }
        }
    }

    @MainActor
    func testCoreReaderMapAbsentAndMetadataLiteralsStayUnknown() throws {
        let expectedStorage: ScriptValue = .object([
            "status": .string("unavailable"), "reason": .string("backingAddressNotRetained")])
        for section in ["__TEXT,__cstring", "__TEXT,__objc_methname"] {
            var snapshot = Self.storageAuthoritySnapshot(shared: false, utf16: true)
            snapshot.stringLiterals = [StringLiteralSummary(id: UUID(), value: "txt", address: 0x2000,
                sourceSection: section, byteLength: 4)]
            snapshot.constantStrings = [:]
            snapshot.stringLiteralCoverage = nil
            let rows = try WorkspaceScriptingAPI.snapshotXRefRead(.object([
                "to": .hex(0x2000)]), snapshot: snapshot, checkpoint: {}).arrayValue
            XCTAssertEqual(rows?.count, 1)
            XCTAssertEqual(rows?.first?["cfStringStorage"], expectedStorage)
            XCTAssertNil(rows?.first?["via"])
        }
        var collision = Self.storageAuthoritySnapshot(shared: true, utf16: false)
        collision.stringLiterals.append(StringLiteralSummary(id: UUID(), value: "txt", address: 0x4000,
            sourceSection: "__TEXT,__cstring", byteLength: 4))
        let objectRows = try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x4000)]), snapshot: collision, checkpoint: {}).arrayValue
        XCTAssertEqual(objectRows?.count, 1)
        XCTAssertEqual(objectRows?.first?["from"], .hex(0x1004))
        XCTAssertNil(objectRows?.first?["cfStringStorage"])
        XCTAssertNil(objectRows?.first?["via"])
        XCTAssertNil(objectRows?.first?["cString"])
    }

    func testCFStringWalkDecodesUTF8AndUTF16AndSkipsMalformed() {
        let section: UInt64 = 0x1_0000_4100
        var memory = SparseMemory()
        memory.put(0x1_0000_0804, Array("%d %@".utf8))
        memory.put(0x1_0000_0900, [0x68, 0x00, 0xE9, 0x00])   // "hé" UTF-16LE
        memory.put(0x1_0000_0a00, [0xFF, 0xFE])                // not UTF-8
        memory.put(section, Self.cfString(flags: 0x7C8, data: 0x1_0000_0804, length: 5))
        memory.put(section + 0x20, Self.cfString(flags: 0x7D0, data: 0x1_0000_0900, length: 2))
        memory.put(section + 0x40, Self.cfString(flags: 0x7C8, data: 0x1_0000_0a00, length: 2))
        memory.put(section + 0x60, Self.cfString(flags: 0x7C8, data: 0x1_0000_0804, length: 1 << 20))
        memory.put(section + 0x80, Self.cfString(flags: 0x7C8, data: 0, length: 0))

        let strings = ImageConstantStringProvider.cfStrings(
            sections: [(section, 0xA0)], pointerSize: 8, rebaseTargets: nil, read: memory.read
        )
        XCTAssertEqual(strings, [section: "%d %@", section + 0x20: "hé"],
                       "invalid UTF-8, oversized length and null data are skipped, never guessed")
    }

    func testCFStringWalkResolvesDataPointerOnlyThroughChainedRebases() {
        let section: UInt64 = 0x1_0000_4100
        var memory = SparseMemory()
        memory.put(0x1_0000_0804, Array("%d %@".utf8))
        // Raw data words are chain entries (garbage as addresses) under chained fixups.
        memory.put(section, Self.cfString(flags: 0x7C8, data: 0x8010_0000_0000_0804, length: 5))
        memory.put(section + 0x20, Self.cfString(flags: 0x7C8, data: 0x1_0000_0804, length: 5))

        let strings = ImageConstantStringProvider.cfStrings(
            sections: [(section, 0x40)],
            pointerSize: 8,
            rebaseTargets: [section + 0x10: 0x1_0000_0804],
            read: memory.read
        )
        XCTAssertEqual(strings, [section: "%d %@"],
                       "a slot the fixup walker did not cover is skipped even if its raw word looks valid")
    }

    func testMapKeepsCFStringKindAndDropsObjectiveCMetadataStrings() {
        let literals = [
            StringLiteralSummary(id: UUID(), value: "%d\n", address: 0x10, sourceSection: "__TEXT,__cstring", byteLength: 4),
            StringLiteralSummary(id: UUID(), value: "init", address: 0x20, sourceSection: "__TEXT,__objc_methname", byteLength: 5),
        ]
        let map = ImageConstantStringProvider.build(stringLiterals: literals, cfStrings: [0x30: "%@"])
        XCTAssertEqual(map, [
            0x10: MacIRConstantString(text: "%d\n", kind: .cString),
            0x30: MacIRConstantString(text: "%@", kind: .cfString),
        ])
        XCTAssertEqual(ImageConstantStringProvider.cfStrings(in: map), [0x30: "%@"])
    }

    // MARK: - CFString backing table (walk)

    private static let backingBase: UInt64 = 0x1_0000_0000

    func testBackingTableRetainsRealDataPointersForMachOAndChainedWalk() throws {
        let fixture = CFStringMachO.make()
        let base = Self.backingBase
        let expected = ImageConstantStringProvider.CFStringBackingTable(
            complete: true,
            backings: [fixture.formatCFString: base + 0x804, fixture.utf16CFString: base + 0x900])
        let source = try fixture.write()
        defer { try? FileManager.default.removeItem(at: source.deletingLastPathComponent()) }
        let snapshot = try AnalysisEngine().analyze(url: source)
        XCTAssertEqual(snapshot.cfStringBackings(in: snapshot.primarySlot), expected)
        XCTAssertEqual(snapshot.constantStrings(in: snapshot.primarySlot)[fixture.formatCFString]?.text, "%d %@")
        XCTAssertEqual(snapshot.constantStrings(in: snapshot.primarySlot)[fixture.utf16CFString]?.text, "hé")

        // Chained variant: the backing equals the rebase target, not the garbage raw word.
        let section: UInt64 = 0x1_0000_4100
        var memory = SparseMemory()
        memory.put(base + 0x804, Array("%d %@".utf8))
        memory.put(base + 0x900, [0x68, 0x00, 0xE9, 0x00])
        memory.put(section, Self.cfString(flags: 0x7C8, data: 0x8010_0000_0000_0804, length: 5))
        memory.put(section + 0x20, Self.cfString(flags: 0x7D0, data: 0x8010_0000_0000_0900, length: 2))
        let walk = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x40)], pointerSize: 8,
            rebaseTargets: [section + 0x10: base + 0x804, section + 0x30: base + 0x900], read: memory.read)
        XCTAssertEqual(walk.table, .init(complete: true, backings: [section: base + 0x804, section + 0x20: base + 0x900]))
        XCTAssertEqual(walk.strings, [section: "%d %@", section + 0x20: "hé"])
        XCTAssertEqual(walk.strings, ImageConstantStringProvider.cfStrings(
            sections: [(section, 0x40)], pointerSize: 8,
            rebaseTargets: [section + 0x10: base + 0x804, section + 0x30: base + 0x900], read: memory.read))

        // Resolved pointer, undecodable contents: backing kept, no text, walk stays complete.
        var invalid = SparseMemory()
        invalid.put(base + 0xA00, [0xFF, 0xFE])
        invalid.put(section, Self.cfString(flags: 0x7C8, data: base + 0xA00, length: 2))
        let undecodable = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x20)], pointerSize: 8, rebaseTargets: nil, read: invalid.read)
        XCTAssertEqual(undecodable.table, .init(complete: true, backings: [section: base + 0xA00]))
        XCTAssertTrue(undecodable.strings.isEmpty)

        // No __cfstring section: complete and empty, not nil.
        var renamed = fixture.bytes
        let name = Data("__cfstring".utf8)
        let range = try XCTUnwrap(renamed.range(of: name))
        renamed.replaceSubrange(range, with: Data("__cfstrinx".utf8))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("NoCFString")
        try renamed.write(to: url)
        let bare = try AnalysisEngine().analyze(url: url)
        XCTAssertEqual(bare.cfStringBackings(in: bare.primarySlot), .init(complete: true, backings: [:]))
    }

    func testBackingWalkReportsIncompleteWhenCappedOrBudgeted() {
        let section: UInt64 = 0x1_0000_4100
        var memory = SparseMemory()
        memory.put(0x1_0000_0804, Array("%d %@".utf8))
        for index in 0..<3 {
            memory.put(section + UInt64(index) * 0x20, Self.cfString(flags: 0x7C8, data: 0x1_0000_0804, length: 5))
        }
        let capped = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x60)], pointerSize: 8, rebaseTargets: nil, read: memory.read, maximumCount: 2)
        XCTAssertFalse(capped.table.complete)
        XCTAssertEqual(capped.strings, [section: "%d %@", section + 0x20: "%d %@"])
        XCTAssertEqual(Set(capped.table.backings.keys), [section, section + 0x20])
        let budgeted = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x60)], pointerSize: 8, rebaseTargets: nil, read: memory.read, maximumBytes: 3)
        XCTAssertFalse(budgeted.table.complete)
        XCTAssertTrue(budgeted.strings.isEmpty)
        let full = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x60)], pointerSize: 8, rebaseTargets: nil, read: memory.read)
        XCTAssertTrue(full.table.complete)
        XCTAssertEqual(full.table.backings.count, 3)
    }

    func testBackingWalkWithUnresolvedPointerIsIncompleteAndKeepsOtherRecords() {
        let section: UInt64 = 0x1_0000_4100
        var memory = SparseMemory()
        memory.put(0x1_0000_0804, Array("%d %@".utf8))
        memory.put(section, Self.cfString(flags: 0x7C8, data: 0x1_0000_0804, length: 5))
        memory.put(section + 0x20, Self.cfString(flags: 0x7C8, data: 0x1_0000_0804, length: 5))
        let viaResolver = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x40)], pointerSize: 8, rebaseTargets: nil,
            resolvePointer: { slot, raw in slot == section + 0x30 ? nil : raw }, read: memory.read)
        XCTAssertFalse(viaResolver.table.complete)
        XCTAssertEqual(viaResolver.table.backings, [section: 0x1_0000_0804])
        let viaChained = ImageConstantStringProvider.walkCFStrings(
            sections: [(section, 0x40)], pointerSize: 8,
            rebaseTargets: [section + 0x10: 0x1_0000_0804], read: memory.read)
        XCTAssertFalse(viaChained.table.complete)
        XCTAssertEqual(viaChained.table.backings, [section: 0x1_0000_0804])
    }

    func testCacheLoaderRetainsBackingTable() throws {
        let fixture = CFStringMachO.make()
        let loaded = try DyldSharedCacheBinaryLoader()
            .loadFromBytes(fixture.cache(), name: "cache", path: "/synthetic/cache")
        let table = try XCTUnwrap(loaded.cfStringBackings)
        XCTAssertTrue(table.complete)
        XCTAssertEqual(table.backings, [fixture.formatCFString: Self.backingBase + 0x10000,
                                        fixture.utf16CFString: Self.backingBase + 0x10008])
    }

    // MARK: - CFString backing table (persistence)

    private static let backingTables: [ImageConstantStringProvider.CFStringBackingTable] = [
        .init(complete: true, backings: [0x4000: 0x3010]), .init(complete: false, backings: [:])]

    private func tableSnapshot(_ table: ImageConstantStringProvider.CFStringBackingTable?) throws -> (WorkspaceSnapshot, CFStringMachO, URL) {
        let fixture = CFStringMachO.make()
        let source = try fixture.write()
        var snapshot = try AnalysisEngine().analyze(url: source)
        snapshot.cfStringBackings = table
        return (snapshot, fixture, source)
    }

    func testBackingTableRoundTripsThroughPayloadManifestPackageAndDatabase() throws {
        for table in Self.backingTables {
            let (snapshot, _, source) = try tableSnapshot(table)
            defer { try? FileManager.default.removeItem(at: source.deletingLastPathComponent()) }
            let payload = AnalysisPayloadCodec.payload(from: snapshot)
            let decodedPayload = try JSONDecoder().decode(AnalysisResultPayload.self, from: JSONEncoder().encode(payload))
            XCTAssertEqual(AnalysisPayloadCodec.snapshot(from: decodedPayload).cfStringBackings(in: .primary), table)
            let manifest = WorkspacePackageAnalysis(snapshot: snapshot)
            let decodedManifest = try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: JSONEncoder().encode(manifest))
            XCTAssertEqual(decodedManifest.imageAnalysis(hexBytes: Data()).cfStringBackings, table)
            let database = try WorkspaceDatabase.inMemory()
            try database.applySchema()
            let saved = try database.saveSnapshot(workspaceName: "Backings", snapshot: snapshot)
            let id = try XCTUnwrap(saved.id)
            XCTAssertEqual(try XCTUnwrap(database.loadSnapshot(workspaceID: id)).cfStringBackings(in: .primary), table)
            let package = source.deletingLastPathComponent().appendingPathComponent("Backings.mscope")
            _ = try database.writePackage(workspaceID: id, documentID: UUID(), to: package)
            XCTAssertEqual(try MacScopeDocumentPackage.openPackage(from: package).snapshot.cfStringBackings(in: .primary), table)
        }
    }

    func testMainFormatDataDecodesWithNilBackingTable() throws {
        let (snapshot, _, source) = try tableSnapshot(nil)
        defer { try? FileManager.default.removeItem(at: source.deletingLastPathComponent()) }
        let payload = try JSONEncoder().encode(AnalysisPayloadCodec.payload(from: snapshot))
        XCTAssertFalse(String(decoding: payload, as: UTF8.self).contains("cfStringBackings"))
        let decoded = try JSONDecoder().decode(AnalysisResultPayload.self, from: payload)
        XCTAssertNil(AnalysisPayloadCodec.snapshot(from: decoded).cfStringBackings(in: .primary))
        let manifest = try JSONEncoder().encode(WorkspacePackageAnalysis(snapshot: snapshot))
        XCTAssertFalse(String(decoding: manifest, as: UTF8.self).contains("cfStringBackings"))
        XCTAssertNil(try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: manifest)
            .imageAnalysis(hexBytes: Data()).cfStringBackings)
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let saved = try database.saveSnapshot(workspaceName: "Legacy", snapshot: snapshot)
        XCTAssertNil(try XCTUnwrap(database.loadSnapshot(workspaceID: XCTUnwrap(saved.id))).cfStringBackings(in: .primary))
        // Tables dropped (a database from before this change): reads back as nil, no throw.
        try database.executeRawForTesting("DROP TABLE constant_cfstring_backings; DROP TABLE constant_cfstring_backing_status;")
        try database.applySchema()
        XCTAssertNil(try database.cfStringBackings(binaryID: 1))
    }

    func testResavingWorkspaceLeavesNoStaleBackingRows() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var id: Int64 = 0
        for (index, table) in ([Self.backingTables[0], Self.backingTables[1], nil] as [ImageConstantStringProvider.CFStringBackingTable?]).enumerated() {
            let (snapshot, _, source) = try tableSnapshot(table)
            defer { try? FileManager.default.removeItem(at: source.deletingLastPathComponent()) }
            if index == 0 {
                id = try XCTUnwrap(database.saveSnapshot(workspaceName: "Resave", snapshot: snapshot).id)
            } else {
                _ = try database.replaceWorkspaceState(
                    workspaceID: id, workspaceName: "Resave", snapshot: snapshot,
                    selectedSidebarItemID: nil, selectedAddress: nil, selectedTool: .project,
                    editorMode: .disassembly, isInspectorPresented: false, sidebarSearchText: "")
            }
            XCTAssertEqual(try XCTUnwrap(database.loadSnapshot(workspaceID: id)).cfStringBackings(in: .primary), table,
                           "save \(index)")
        }
    }

    func testBackingTableValidationRejectsDuplicatesAndOversize() throws {
        let duplicate = Data(#"{"complete":true,"backings":[{"address":1,"backing":2},{"address":1,"backing":3}]}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(ImageConstantStringProvider.CFStringBackingTable.self, from: duplicate))
        let table = ImageConstantStringProvider.CFStringBackingTable(
            complete: true, backings: Dictionary(uniqueKeysWithValues:
                (0...UInt64(ImageConstantStringProvider.maximumCFStringCount)).map { ($0, $0) }))
        XCTAssertThrowsError(try ImageConstantStringProvider.validated(table))
    }

    // MARK: - Synthetic image end to end

    func testFixtureNSLogConstantCFStringRecoversTwoVariadicArguments() throws {
        let fixture = CFStringMachO.make()
        let snapshot = try AnalysisEngine().analyze(url: fixture.write())

        let map = snapshot.constantStrings(in: snapshot.primarySlot)
        XCTAssertEqual(map[fixture.formatCFString], MacIRConstantString(text: "%d %@", kind: .cfString))
        XCTAssertEqual(map[fixture.utf16CFString], MacIRConstantString(text: "hé", kind: .cfString))
        XCTAssertEqual(map[fixture.printfFormat], MacIRConstantString(text: "%d\n", kind: .cString))

        let input = snapshot.pseudocodeRenderInput(selectedAddress: fixture.mainAddress, in: snapshot.primarySlot)
        XCTAssertEqual(input.constantStrings, map, "the render input carries the stored map")
        let function = PseudocodePrinter().buildFunction(
            functionName: input.functionName,
            startAddress: input.startAddress,
            objcSelectors: input.objcSelectors,
            constantStrings: input.constantStrings,
            instructions: input.instructions
        )
        let frame = try XCTUnwrap(function.instructions.lazy.compactMap { instruction -> MacIRCallFrame? in
            guard case let .call(frame, _) = instruction.operation, frame.target == "_NSLog" else { return nil }
            return frame
        }.first, "NSLog call not found in \(input.instructions.map { "\($0.mnemonic) \($0.operands)" })")
        guard case let .formatString(evidence) = frame.tailCountEvidence else {
            return XCTFail("expected format-string evidence, got \(String(describing: frame.tailCountEvidence))")
        }
        XCTAssertEqual(evidence.formatStringKind, .cfString)
        XCTAssertEqual(evidence.formatAddress, fixture.formatCFString)
        XCTAssertEqual(evidence.argumentTypes, ["int", "id"])
        XCTAssertEqual(frame.expectedTailCount, 2)
        let rendered = try XCTUnwrap(frame.completeKnownVariadicRenderValues())
        XCTAssertEqual(rendered.count, 3)
        XCTAssertEqual(rendered.first, .symbol("@\"%d %@\""))
    }

    func testExportPseudocodeShowsPrintfAndNSLogArguments() throws {
        let fixture = CFStringMachO.make()
        let snapshot = try AnalysisEngine().analyze(url: fixture.write())
        let text = DocumentExportService().renderPseudocode(snapshot: snapshot, selectedAddress: fixture.mainAddress)
        XCTAssertTrue(text.contains("printf(\"%d\\n\", "), text)
        XCTAssertTrue(text.contains("NSLog(@\"%d %@\", "), text)
    }

    func testMapIsStoredOncePerImageAndSurvivesTheWorkerCodec() throws {
        let fixture = CFStringMachO.make()
        var snapshot = try AnalysisEngine().analyze(url: fixture.write())
        let stored = snapshot.constantStrings

        // Renders read the stored map: with the literal table emptied afterwards, the export
        // still resolves both formats, so nothing is rebuilt from `stringLiterals` per render.
        snapshot.stringLiterals = []
        let text = DocumentExportService().renderPseudocode(snapshot: snapshot, selectedAddress: fixture.mainAddress)
        XCTAssertTrue(text.contains("printf(\"%d\\n\", "), text)
        XCTAssertTrue(text.contains("NSLog(@\"%d %@\", "), text)

        // Worker boundary: only the CFString part travels; the C-string part is rebuilt once on decode.
        let original = try AnalysisEngine().analyze(url: fixture.write())
        let payload = AnalysisPayloadCodec.payload(from: original)
        XCTAssertEqual(payload.constantCFStrings, [fixture.formatCFString: "%d %@", fixture.utf16CFString: "hé"])
        let decoded = try JSONDecoder().decode(AnalysisResultPayload.self, from: JSONEncoder().encode(payload))
        XCTAssertEqual(AnalysisPayloadCodec.snapshot(from: decoded).constantStrings, stored)
    }

    func testDatabaseAndPackageReopenRetainFormatsBeforeRehydrate() throws {
        let fixture = CFStringMachO.make()
        let source = try fixture.write()
        defer { try? FileManager.default.removeItem(at: source.deletingLastPathComponent()) }
        var snapshot = try AnalysisEngine().analyze(url: source)
        snapshot.constantStrings[0xFEDC_BA98_7654_3210] = .init(text: "embedded\0zero", kind: .cfString)
        let expected = snapshot.constantStrings
        let packageURL = source.deletingLastPathComponent().appendingPathComponent("Formats.mscope")
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let workspace = try database.saveSnapshot(workspaceName: "Formats", snapshot: snapshot)
        let workspaceID = try XCTUnwrap(workspace.id)
        let reloaded = try XCTUnwrap(database.loadSnapshot(workspaceID: workspaceID))
        XCTAssertEqual(reloaded.constantStrings, expected)
        assertFormats(reloaded, at: fixture.mainAddress)
        _ = try database.writePackage(workspaceID: workspaceID, documentID: UUID(), to: packageURL)
        let opened = try MacScopeDocumentPackage.openPackage(from: packageURL)
        XCTAssertEqual(opened.snapshot.constantStrings, expected)
        assertFormats(opened.snapshot, at: fixture.mainAddress)
        let destination = try WorkspaceDatabase.inMemory()
        try destination.applySchema()
        let imported = try destination.importPackage(from: packageURL)
        XCTAssertEqual(imported.snapshot.constantStrings, expected)
        assertFormats(imported.snapshot, at: fixture.mainAddress)
        let again = try XCTUnwrap(destination.loadSnapshot(workspaceID: XCTUnwrap(imported.workspace.id)))
        XCTAssertEqual(again.constantStrings, expected)
    }

    func testConstantStringsStayImageLocalAcrossPackageAndDatabase() throws {
        let fixture = CFStringMachO.make()
        let source = try fixture.write()
        defer { try? FileManager.default.removeItem(at: source.deletingLastPathComponent()) }
        var snapshot = try AnalysisEngine().analyze(url: source)
        let first = try XCTUnwrap(snapshot.binaries.first)
        let second = BinaryImage(id: UUID(), name: first.name, path: first.path, kind: first.kind,
                                 architecture: first.architecture, metadata: first.metadata,
                                 artifactIdentity: first.artifactIdentity,
                                 preferredSegmentLayout: first.preferredSegmentLayout,
                                 artifactIntegrityState: first.artifactIntegrityState,
                                 slot: ImageSlot(rawValue: 1))
        snapshot.binaries.append(second)
        var analysis = ImageAnalysis()
        analysis.imageBytes = fixture.bytes
        analysis.constantStrings = [fixture.formatCFString: .init(text: "different %@", kind: .cfString)]
        snapshot.analysisBySlot[second.slot] = analysis
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let saved = try database.saveSnapshot(workspaceName: "Two images", snapshot: snapshot)
        let package = source.deletingLastPathComponent().appendingPathComponent("Two.mscope")
        _ = try database.writePackage(workspaceID: XCTUnwrap(saved.id), documentID: UUID(), to: package)
        let opened = try MacScopeDocumentPackage.openPackage(from: package).snapshot
        XCTAssertEqual(opened.constantStrings(in: .primary)[fixture.formatCFString]?.text, "%d %@")
        XCTAssertEqual(opened.constantStrings(in: second.slot), analysis.constantStrings)
    }

    func testLegacyDatabaseAndPackageRebuildOnlyPersistedCStringFacts() throws {
        let literal = StringLiteralSummary(id: UUID(), value: "%d", address: 0x20,
                                          sourceSection: "__TEXT,__cstring", byteLength: 3)
        let original = WorkspacePackageAnalysis(stringLiterals: [literal])
        let encoded = try JSONEncoder().encode(original)
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("constantCFStrings"))
        let legacy = try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: encoded)
        XCTAssertEqual(legacy.imageAnalysis(hexBytes: Data()).constantStrings,
                       [0x20: .init(text: "%d", kind: .cString)])
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        try database.executeRawForTesting("DROP TABLE constant_cfstrings;")
        try database.applySchema()
        XCTAssertEqual(try database.constantCFStrings(binaryID: 1), [:])
        XCTAssertEqual(try database.userVersion(), WorkspaceDatabase.schemaVersion)
    }

    func testPersistedCFStringValidationRejectsDuplicateAddressesAndOversizedText() throws {
        let entry = ImageConstantStringProvider.PersistedCFString(address: 1, text: "a")
        XCTAssertThrowsError(try ImageConstantStringProvider.validated([entry, entry]))
        XCTAssertThrowsError(try ImageConstantStringProvider.validated([
            .init(address: 1, text: String(repeating: "x", count: ImageConstantStringProvider.maximumCFStringLength + 1))
        ]))
        let malformed = Data(#"{"constantCFStrings":[{"address":1,"text":"a"},{"address":1,"text":"b"}]}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: malformed))
    }

    func testCacheCFStringsUseSharedMappingsAndDeclaredSlideEncoding() throws {
        let fixture = CFStringMachO.make()
        let cache = fixture.cache()
        let loaded = try DyldSharedCacheBinaryLoader().loadFromBytes(cache, name: "cache", path: "/synthetic/cache")
        XCTAssertEqual(loaded.constantCFStrings,
                       [fixture.formatCFString: "%d %@", fixture.utf16CFString: "hé"])
        var unsupported = cache
        unsupported.replaceSubrange(0x280..<0x284, with: [3, 0, 0, 0])
        XCTAssertTrue(try DyldSharedCacheBinaryLoader()
            .loadFromBytes(unsupported, name: "cache", path: "/synthetic/cache").constantCFStrings.isEmpty)
        var missing = cache
        // Keep both mappings valid, but redirect the contents beyond the admitted shared region.
        missing.replaceSubrange(0x400 + 0x4110..<0x400 + 0x4118,
                                with: [0, 0, 2, 0, 0, 0, 0x40, 0])
        let unavailable = try DyldSharedCacheBinaryLoader()
            .loadFromBytes(missing, name: "cache", path: "/synthetic/cache").constantCFStrings
        XCTAssertNil(unavailable[fixture.formatCFString])
        XCTAssertEqual(unavailable[fixture.utf16CFString], "hé")
    }

    func testCacheCFStringsRefuseUnlinkedSlotsAndMalformedSlidePages() throws {
        let fixture = CFStringMachO.make()
        let cache = fixture.cache()
        for (offset, replacement) in [
            (0x288, [UInt8](repeating: 0, count: 4)), // no page-start authority
            (0x288, [UInt8](repeating: 0xFF, count: 4)), // table exceeds declared slide info
            (0x284, [UInt8](repeating: 0, count: 4)), // invalid page size
            (0x2A0, [UInt8(0xFF), 0xFF]), // NO_REBASE
            (0x2A0, [UInt8(0x11), 0x01]), // misaligned first slot
            (0x400 + 0x4136, [UInt8(0xF0), 0xFF]), // chain jumps beyond its page
        ] {
            var malformed = cache
            malformed.replaceSubrange(offset..<offset + replacement.count, with: replacement)
            XCTAssertTrue(try DyldSharedCacheBinaryLoader()
                .loadFromBytes(malformed, name: "cache", path: "/synthetic/cache").constantCFStrings.isEmpty,
                          "invalid slide field at \(offset)")
        }
        var unlinked = cache
        unlinked.replaceSubrange(0x2A0..<0x2A2, with: [0x30, 0x01]) // only the second data slot
        let strings = try DyldSharedCacheBinaryLoader()
            .loadFromBytes(unlinked, name: "cache", path: "/synthetic/cache").constantCFStrings
        XCTAssertNil(strings[fixture.formatCFString])
        XCTAssertEqual(strings[fixture.utf16CFString], "hé")
    }

    func testCFStringWalkRefusesShortReadsAndOverflowedSection() {
        XCTAssertTrue(ImageConstantStringProvider.cfStrings(
            sections: [(UInt64.max - 15, 64), (0x1000, 32)], pointerSize: 8,
            rebaseTargets: nil, read: { _, _ in Data([0]) }
        ).isEmpty)
    }

    private func assertFormats(_ snapshot: WorkspaceSnapshot, at address: UInt64,
                               file: StaticString = #filePath, line: UInt = #line) {
        let text = DocumentExportService().renderPseudocode(snapshot: snapshot, selectedAddress: address)
        XCTAssertTrue(text.contains("printf(\"%d\\n\", "), text, file: file, line: line)
        XCTAssertTrue(text.contains("NSLog(@\"%d %@\", "), text, file: file, line: line)
    }

    // MARK: - Helpers

    private static func cfString(flags: UInt64, data: UInt64, length: UInt64) -> [UInt8] {
        [0, flags, data, length].flatMap { word in (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) } }
    }

    private struct SparseMemory {
        var regions: [(UInt64, [UInt8])] = []
        mutating func put(_ address: UInt64, _ bytes: [UInt8]) { regions.append((address, bytes)) }
        func read(_ address: UInt64, _ count: Int) -> Data? {
            for (base, bytes) in regions where address >= base && address - base + UInt64(count) <= UInt64(bytes.count) {
                let start = Int(address - base)
                return Data(bytes[start ..< start + count])
            }
            return nil
        }
    }
}

/// A small arm64 executable: `_main` calls `NSLog(@"%d %@", 5, @"hé")` then `printf("%d\n", 7)`,
/// with `_NSLog`/`_printf` as in-image `ret` stubs named by LC_SYMTAB. `__cfstring` holds an 8-bit
/// object (format) and a UTF-16 object (argument) with raw (non-chained) data pointers.
private struct CFStringMachO {
    static let imageBase: UInt64 = 0x1_0000_0000
    let bytes: Data
    var mainAddress: UInt64 { Self.imageBase + 0x400 }
    var printfFormat: UInt64 { Self.imageBase + 0x800 }
    var formatCFString: UInt64 { Self.imageBase + 0x4100 }
    var utf16CFString: UInt64 { Self.imageBase + 0x4120 }

    static func make() -> CFStringMachO {
        let base = imageBase
        let code: [UInt32] = [
            0xD100_83FF, // 400 sub  sp, sp, #0x20
            0x5280_00A8, // 404 mov  w8, #0x5
            0xF900_03E8, // 408 str  x8, [sp]
            0x9000_0029, // 40c adrp x9, base+0x4000
            0x9104_8129, // 410 add  x9, x9, #0x120      ; @"hé"
            0xF900_07E9, // 414 str  x9, [sp, #0x8]
            0x9000_0020, // 418 adrp x0, base+0x4000
            0x9104_0000, // 41c add  x0, x0, #0x100      ; @"%d %@"
            0x9400_0009, // 420 bl   _NSLog (0x444)
            0x5280_00E8, // 424 mov  w8, #0x7
            0xF900_03E8, // 428 str  x8, [sp]
            0x9000_0000, // 42c adrp x0, base
            0x9120_0000, // 430 add  x0, x0, #0x800      ; "%d\n"
            0x9400_0005, // 434 bl   _printf (0x448)
            0x9100_83FF, // 438 add  sp, sp, #0x20
            0x5280_0000, // 43c mov  w0, #0x0
            0xD65F_03C0, // 440 ret
            0xD65F_03C0, // 444 _NSLog: ret
            0xD65F_03C0, // 448 _printf: ret
        ]
        var file = [UInt8](repeating: 0, count: 0x8000)
        func put(_ offset: Int, _ bytes: [UInt8]) { file.replaceSubrange(offset ..< offset + bytes.count, with: bytes) }
        func le32(_ value: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) } }
        func le64(_ value: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) } }
        func name16(_ text: String) -> [UInt8] { Array(text.utf8) + [UInt8](repeating: 0, count: 16 - text.utf8.count) }
        func section(_ name: String, _ segment: String, address: UInt64, size: UInt64, offset: UInt32,
                     align: UInt32, flags: UInt32) -> [UInt8] {
            name16(name) + name16(segment) + le64(address) + le64(size) + le32(offset) + le32(align)
                + le32(0) + le32(0) + le32(flags) + le32(0) + le32(0) + le32(0)
        }
        func segment(_ name: String, address: UInt64, size: UInt64, offset: UInt64, prot: UInt32,
                     sections: [[UInt8]]) -> [UInt8] {
            le32(MachOConstants.loadCommandSegment64) + le32(UInt32(72 + 80 * sections.count)) + name16(name)
                + le64(address) + le64(size) + le64(offset) + le64(size) + le32(prot) + le32(prot)
                + le32(UInt32(sections.count)) + le32(0) + sections.flatMap { $0 }
        }

        let codeBytes = code.flatMap { le32($0) }
        let text = segment("__TEXT", address: base, size: 0x4000, offset: 0, prot: 5, sections: [
            section("__text", "__TEXT", address: base + 0x400, size: UInt64(codeBytes.count), offset: 0x400, align: 2,
                    flags: MachOConstants.sectionAttributePureInstructions | MachOConstants.sectionAttributeSomeInstructions),
            section("__cstring", "__TEXT", address: base + 0x800, size: 0x0A, offset: 0x800, align: 0, flags: 0x2),
            section("__ustring", "__TEXT", address: base + 0x900, size: 0x06, offset: 0x900, align: 1, flags: 0),
        ])
        let data = segment("__DATA", address: base + 0x4000, size: 0x4000, offset: 0x4000, prot: 3, sections: [
            section("__cfstring", "__DATA", address: base + 0x4100, size: 0x40, offset: 0x4100, align: 3, flags: 0),
        ])
        let main = le32(MachOConstants.loadCommandMain) + le32(24) + le64(0x400) + le64(0)
        let symbols: [(String, UInt64)] = [("_main", base + 0x400), ("_NSLog", base + 0x444), ("_printf", base + 0x448)]
        var strtab: [UInt8] = [0]
        var nlist: [UInt8] = []
        for (name, address) in symbols {
            nlist += le32(UInt32(strtab.count)) + [MachOConstants.symbolTypeSection | MachOConstants.symbolExternal, 1, 0, 0]
                + le64(address)
            strtab += Array(name.utf8) + [0]
        }
        let symtabOffset = 0x8000
        let symtab = le32(MachOConstants.loadCommandSymtab) + le32(24) + le32(UInt32(symtabOffset))
            + le32(UInt32(symbols.count)) + le32(UInt32(symtabOffset + nlist.count)) + le32(UInt32(strtab.count))
        let commands = text + data + main + symtab
        let header = le32(0xFEED_FACF) + le32(UInt32(bitPattern: MachOConstants.cpuTypeARM64)) + le32(0)
            + le32(MachOConstants.fileTypeExecute) + le32(4) + le32(UInt32(commands.count)) + le32(0) + le32(0)
        put(0, header + commands)
        put(0x400, codeBytes)
        put(0x800, Array("%d\n".utf8) + [0] + Array("%d %@".utf8) + [0])
        put(0x900, [0x68, 0x00, 0xE9, 0x00, 0x00, 0x00])
        func cf(_ flags: UInt64, _ data: UInt64, _ length: UInt64) -> [UInt8] {
            le64(0) + le64(flags) + le64(data) + le64(length)
        }
        put(0x4100, cf(0x7C8, base + 0x804, 5) + cf(0x7D0, base + 0x900, 2))
        file += nlist + strtab
        return CFStringMachO(bytes: Data(file))
    }

    /// A cache wrapper with a second, shared mapping outside the image projection. CF data
    /// pointers use slide-v5 offsets; the ordinary per-image C strings retain their addresses.
    func cache() -> Data {
        var output = Data(repeating: 0, count: 0x400)
        func put(_ at: Int, _ value: UInt64, size: Int = 8) {
            output.replaceSubrange(at..<at + size, with: (0..<size).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) })
        }
        output.replaceSubrange(0..<16, with: Array("dyld_v1  arm64e".utf8) + [0])
        put(16, 0x200, size: 4); put(20, 2, size: 4)
        put(24, 0x300, size: 4); put(28, 1, size: 4)
        put(0xE0, Self.imageBase)
        put(0x138, 0x240, size: 4); put(0x13C, 1, size: 4)
        put(0x200, Self.imageBase); put(0x208, UInt64(bytes.count)); put(0x210, 0x400)
        put(0x218, 3, size: 4); put(0x21C, 3, size: 4)
        put(0x220, Self.imageBase + 0x10000); put(0x228, 16); put(0x230, UInt64(0x400 + bytes.count))
        put(0x238, 1, size: 4); put(0x23C, 1, size: 4)
        put(0x240, Self.imageBase); put(0x248, UInt64(bytes.count)); put(0x250, 0x400)
        let pageCount = (bytes.count + 4095) / 4096
        put(0x258, 0x280); put(0x260, UInt64(24 + 2 * pageCount))
        put(0x280, 5, size: 4); put(0x284, 4096, size: 4)
        put(0x288, UInt64(pageCount), size: 4); put(0x290, Self.imageBase)
        for page in 0..<pageCount { put(0x298 + 2 * page, 0xFFFF, size: 2) }
        put(0x2A0, 0x110, size: 2) // page 4: first CFString data slot; next is 32 bytes later
        put(0x300, Self.imageBase); put(0x318, 0x330, size: 4)
        let path = Array("/usr/lib/libCFStrings.dylib".utf8) + [0]
        output.replaceSubrange(0x330..<0x330 + path.count, with: path)
        output.append(bytes)
        let reader = LittleEndianReader(bytes)
        var command = 32
        for _ in 0..<4 {
            let kind = (try? reader.u32(command)) ?? 0
            if kind == MachOConstants.loadCommandSegment64 {
                put(0x400 + command + 40, ((try? reader.u64(command + 40)) ?? 0) + 0x400)
                let sections = (try? reader.u32(command + 64)) ?? 0
                for index in 0..<Int(sections) {
                    let field = command + 72 + index * 80 + 48
                    put(0x400 + field, UInt64((try? reader.u32(field)) ?? 0) + 0x400, size: 4)
                }
            } else if kind == MachOConstants.loadCommandSymtab {
                for field in [8, 16] {
                    put(0x400 + command + field, UInt64((try? reader.u32(command + field)) ?? 0) + 0x400, size: 4)
                }
            }
            command += Int((try? reader.u32(command + 4)) ?? 0)
        }
        put(0x400 + 0x4110, 0x0040_0000_0001_0000)
        put(0x400 + 0x4130, 0x8000_0000_0001_0008) // authenticated shared-cache rebase
        output.append(contentsOf: Array("%d %@".utf8) + [0, 0, 0, 0x68, 0, 0xE9, 0, 0, 0, 0, 0])
        return output
    }

    func write() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("CFStringMachO")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try bytes.write(to: url)
        return url
    }
}
