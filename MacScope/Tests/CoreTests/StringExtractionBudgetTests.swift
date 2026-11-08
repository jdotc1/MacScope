import Foundation
import XCTest
@testable import MacScope

@MainActor
final class StringExtractionBudgetTests: XCTestCase {
    func testRehydrationAfterDatabaseReloadPreservesIncompleteCoverageAndEdges() throws {
        let bytes = fields(["old", "late %d"])
        let section = SectionSummary(id: UUID(), name: "__TEXT,__cstring", address: 0x1000,
            size: UInt64(bytes.count), fileOffset: 0, isExecutable: false, containsCStringLiterals: true)
        let old = StringLiteralSummary(id: UUID(), value: "old", address: 0x1000,
                                       sourceSection: section.name, byteLength: 3)
        let ref = XRef(id: UUID(), from: 0x200, to: 0x1004, kind: XRefKind.data)
        var persisted = ImageAnalysis()
        persisted.stringLiterals = [old]; persisted.xrefs = [ref]; persisted.imageBytes = bytes
        persisted.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        let binary = BinaryImage(id: UUID(), name: "rehydration", path: "/synthetic/rehydration",
                                 kind: "synthetic fixture", architecture: "arm64", slot: .primary)
        let snapshot = WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: persisted])
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let workspaceID = try XCTUnwrap(database.saveSnapshot(workspaceName: "Rehydration", snapshot: snapshot).id)
        let restored = try XCTUnwrap(database.loadSnapshot(workspaceID: workspaceID)?.analysis(in: .primary))
        XCTAssertEqual(restored.stringLiteralCoverage, persisted.stringLiteralCoverage)
        let id = UUID()
        let loader = RehydrationLoaderProducts(requestID: id, requestedSliceIndex: nil,
            imageByteCount: bytes.count, sliceOffset: 0, sliceSize: UInt64(bytes.count), sections: [section],
            mappings: FileAddressMapping.verifiedMappings(from: [section], payloadLength: bytes.count))
        let codec = AnalysisRehydrateWireCodec()
        let decoded = try codec.decodeLoaderReply(codec.encodeLoaderReply(.success(loader)), requestID: id,
            requestImageByteCount: bytes.count, requestedSliceIndex: nil)
        let result = try RehydrationDerivedProducts.rebuild(persisted: restored, loader: decoded,
            imageBytes: bytes, cancellation: .never)
        XCTAssertEqual(result.stringLiterals.map(\.value), ["old", "late %d"])
        XCTAssertEqual(result.xrefs, [ref])
        XCTAssertEqual(result.constantStrings[ref.to]?.text, "late %d")
        XCTAssertEqual(result.stringLiteralCoverage, persisted.stringLiteralCoverage)
        XCTAssertEqual(try RehydrationDerivedProducts.rebuild(persisted: result, loader: decoded,
            imageBytes: bytes, cancellation: .never).stringLiterals, result.stringLiterals)
    }

    func testFreshAnalysisRecoversReferencedStringPastParserCap() throws {
        let cap = MachORecoveryLimits.maximumStringLiterals
        var fixture = MachOFixture.makeExecutableWithStringSections([repeated(cap) + fields(["late %d"])])
        let address = try XCTUnwrap(fixture.stringLiteralAddress) + UInt64(cap * 2)
        let displacement = UInt32(address - fixture.baseAddress)
        XCTAssertLessThan(displacement, 1 << 20)
        let instruction: UInt32 = 0x1000_0000 | ((displacement & 3) << 29) | ((displacement >> 2) << 5)
        for index in 0..<4 {
            fixture.bytes[fixture.codeOffset + index] = UInt8(truncatingIfNeeded: instruction >> (index * 8))
        }
        let parsed = try MachOParser().parse(fixture.bytes)
        XCTAssertEqual(parsed.stringLiterals.count, cap)
        XCTAssertFalse(parsed.stringLiterals.contains { $0.address == address })
        let url = try temporaryFile(fixture.bytes)
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let snapshot = try AnalysisEngine().analyze(url: url)
        XCTAssertEqual(snapshot.stringLiteralCoverage, .incomplete(.stringCountLimitReached))
        XCTAssertEqual(snapshot.constantStrings[address]?.text, "late %d")
        XCTAssertTrue(snapshot.xrefs.contains { $0.to == address && $0.kind == XRefKind.data })
    }

    func testReferencedRecoveryBeyondDefaultCapReachesWireConsumers() throws {
        let cap = MachORecoveryLimits.maximumStringLiterals
        let bytes = repeated(cap) + fields(["late %d"])
        let section = SectionSummary(id: UUID(), name: "__TEXT,__cstring", address: 0x1000,
            size: UInt64(bytes.count), fileOffset: 0, isExecutable: false, containsCStringLiterals: true)
        let rows = (0..<cap).map { index in
            StringLiteralSummary(id: UUID(), value: "a", address: 0x1000 + UInt64(index * 2),
                                 sourceSection: section.name, byteLength: 1)
        }
        let target = 0x1000 + UInt64(cap * 2)
        let ref = XRef(id: UUID(), from: 0x200, to: target, kind: XRefKind.data)
        let recovered = try ReferencedStringRecovery.recover(retained: rows,
            coverage: .incomplete(.stringCountLimitReached), references: [ref], sections: [section],
            bytes: bytes, sliceOffset: 0, sliceSize: nil, overlay: .empty, checkpoint: {})
        XCTAssertEqual(recovered.count, cap + 1)
        XCTAssertEqual(recovered.first, rows.first)
        XCTAssertEqual(recovered.last?.value, "late %d")
        var analysis = ImageAnalysis()
        analysis.stringLiterals = recovered; analysis.sections = [section]; analysis.xrefs = [ref]
        analysis.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: recovered, cfStrings: [:])
        let image = BinaryImage(id: UUID(), name: "late", path: "/synthetic", kind: "Mach-O executable",
                                architecture: "arm64", slot: .primary)
        let snapshot = WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis])
        let codec = PayloadWireCodec()
        let decoded = try codec.decodeReply(codec.encodeReply(.success(snapshot)))
        XCTAssertEqual(decoded.constantStrings[target]?.text, "late %d")
        XCTAssertEqual(decoded.stringLiteralCoverage, analysis.stringLiteralCoverage)
        XCTAssertEqual(decoded.sections.first?.containsCStringLiterals, true)
    }

    func testReferencedRecoveryPreservesRowsAndRejectsPatchedFields() throws {
        let bytes = Data([111, 108, 100, 0, 108, 97, 116, 101, 0])
        let section = SectionSummary(id: UUID(), name: "__TEXT,__cstring", address: 0x1000,
            size: UInt64(bytes.count), fileOffset: 0, isExecutable: false, containsCStringLiterals: true)
        let old = StringLiteralSummary(id: UUID(), value: "old", address: 0x1000,
                                       sourceSection: section.name, byteLength: 3)
        let ref = XRef(id: UUID(), from: 0x2000, to: 0x1004, kind: XRefKind.data)
        func recover(_ overlay: BytePatchOverlay) throws -> [StringLiteralSummary] {
            try ReferencedStringRecovery.recover(retained: [old], coverage: .incomplete(.stringCountLimitReached),
                references: [ref], sections: [section], bytes: bytes, sliceOffset: 0, sliceSize: nil,
                overlay: overlay, checkpoint: {})
        }
        let result = try recover(.empty)
        XCTAssertEqual(result.map(\.value), ["old", "late"])
        XCTAssertEqual(result.first, old)
        let patch = try BytePatchOverlay(patches: [0x1005: BytePatch(bytes: [88])])
        XCTAssertEqual(try recover(patch), [old])
        XCTAssertEqual(try ReferencedStringRecovery.recover(retained: result,
            coverage: .incomplete(.stringCountLimitReached), references: [ref], sections: [section],
            bytes: bytes, sliceOffset: 0, sliceSize: nil, overlay: .empty, checkpoint: {}), result)
    }

    func testReferencedRecoveryUsesParserSectionPriority() throws {
        let objc = SectionSummary(id: UUID(), name: "__TEXT,__objc_methname", address: 0x1000,
            size: 5, fileOffset: 0, isExecutable: false, containsCStringLiterals: true)
        let cstring = SectionSummary(id: UUID(), name: "__TEXT,__cstring", address: 0x2000,
            size: 9, fileOffset: 5, isExecutable: false, containsCStringLiterals: true)
        let ordinary = StringLiteralSummary(id: UUID(), value: "one", address: 0x2000,
                                            sourceSection: cstring.name, byteLength: 3)
        let method = StringLiteralSummary(id: UUID(), value: "meth", address: 0x1000,
                                          sourceSection: objc.name, byteLength: 4)
        let ref = XRef(id: UUID(), from: 1, to: 0x2004, kind: XRefKind.data)
        let rows = try ReferencedStringRecovery.recover(retained: [ordinary, method],
            coverage: .incomplete(.stringCountLimitReached), references: [ref],
            sections: [objc, cstring], bytes: Data("meth\0one\0late\0".utf8),
            sliceOffset: 0, sliceSize: nil, overlay: .empty, checkpoint: {})
        XCTAssertEqual(rows.map(\.value), ["one", "late", "meth"])
    }

    func testReferencedRecoveryRejectsInteriorUnknownAndCancelledReads() throws {
        let bytes = Data([97, 98, 0])
        var section = SectionSummary(id: UUID(), name: "s", address: 0x1000, size: 3,
                                     fileOffset: 0, isExecutable: false, containsCStringLiterals: true)
        let interior = XRef(id: UUID(), from: 1, to: 0x1001, kind: XRefKind.data)
        func recover(_ section: SectionSummary, _ checkpoint: () throws -> Void) throws -> [StringLiteralSummary] {
            try ReferencedStringRecovery.recover(retained: [], coverage: .incomplete(.stringCountLimitReached),
                references: [interior], sections: [section], bytes: bytes, sliceOffset: 0,
                sliceSize: nil, overlay: .empty, checkpoint: checkpoint)
        }
        XCTAssertTrue(try recover(section, {}).isEmpty)
        section.containsCStringLiterals = nil
        XCTAssertTrue(try recover(section, {}).isEmpty)
        XCTAssertThrowsError(try recover(section, { throw CancellationError() }))
    }

    private func discoverySnapshot(_ fixture: MachOFixture, cap: Int) throws -> WorkspaceSnapshot {
        let parsed = try MachOParser().parse(fixture.bytes, options: MachOParseOptions(
            recoverObjectiveCMetadata: false, recoverSwiftMetadata: false,
            parseCodeSignature: false, maximumStringLiterals: cap))
        var analysis = ImageAnalysis()
        analysis.stringLiterals = parsed.stringLiterals.map {
            StringLiteralSummary(id: UUID(), value: $0.value, address: $0.address,
                                 sourceSection: $0.sourceSection, byteLength: $0.byteLength)
        }
        analysis.stringLiteralCoverage = parsed.stringLiteralCoverage
        analysis.imageBytes = fixture.bytes
        return WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis])
    }

    func testDiscoveryFindsStringsPastRetentionAndReportsExactCount() throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([repeated(8) + fields(["config.ghostty"])])
        let snapshot = try discoverySnapshot(fixture, cap: 8)
        let info = try WorkspaceScriptingAPI.stringCountFields(snapshot)
        XCTAssertEqual(info["stringRetainedCount"], .int(8))
        XCTAssertEqual(info["stringCount"], .int(9))
        XCTAssertEqual(info["stringCountCapped"], .bool(true))
        let result = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "contains": .string("config.ghostty"),
        ]), snapshot: snapshot)
        XCTAssertEqual(try values(result["rows"]), ["config.ghostty"])
        XCTAssertEqual(result["total"], .int(1))
        XCTAssertEqual(result["sourceComplete"], .bool(true))
    }

    func testDiscoveryPastDefaultCapAndMalformedSourceStaysUnknown() throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([
            repeated(MachORecoveryLimits.maximumStringLiterals) + fields(["beyond-cap"]),
        ])
        let snapshot = try discoverySnapshot(fixture, cap: MachORecoveryLimits.maximumStringLiterals)
        let page = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "contains": .string("beyond-cap"),
        ]), snapshot: snapshot)
        XCTAssertEqual(try values(page["rows"]), ["beyond-cap"])
        XCTAssertEqual(page["total"], .int(1))
        XCTAssertEqual(try WorkspaceScriptingAPI.stringCountFields(snapshot)["stringCount"],
                       .int(Int64(MachORecoveryLimits.maximumStringLiterals + 1)))

        let malformed = try discoverySnapshot(MachOFixture.makeExecutableWithStringSections([
            fields(["valid"]) + Data("unterminated".utf8),
        ]), cap: 1)
        let incomplete = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true),
        ]), snapshot: malformed)
        XCTAssertEqual(try values(incomplete["rows"]), ["valid"])
        XCTAssertEqual(incomplete["sourceComplete"], .bool(false))
        XCTAssertEqual(incomplete["total"], .null)
    }

    func testFlatDiscoveryRefusalDoesNotMisstateExhaustedBudget() throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([
            Data(repeating: 97, count: 8_388_609) + Data([0]),
        ])
        let snapshot = try discoverySnapshot(fixture, cap: 0)
        let source = try XCTUnwrap(try WorkspaceScriptingAPI.snapshotStringDiscovery(snapshot, checkpoint: {}))
        let filter = WorkspaceScriptingAPI.StringListFilter(section: nil, contains: "needle")
        XCTAssertThrowsError(try WorkspaceScriptingAPI.discoveryRows(source, filter: filter,
                                                                     limit: nil, checkpoint: {})) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else {
                return XCTFail("expected a structured continuation refusal")
            }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertNil(refusal.budget)
            XCTAssertTrue(refusal.detail.contains("page:true"))
        }
    }

    func testIncompleteFlatScanDoesNotReturnRetainedMatchAsComplete() throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([
            fields(["needle"]) + Data(repeating: 97, count: 8_388_609) + Data([0]),
        ])
        let snapshot = try discoverySnapshot(fixture, cap: 1)
        XCTAssertEqual(snapshot.stringLiterals.map(\.value), ["needle"])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "contains": .string("needle"),
        ]), snapshot: snapshot)) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else {
                return XCTFail("expected a continuation refusal")
            }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertTrue(refusal.detail.contains("page:true"))
        }
    }

    func testFilteredFlatReadRefusesMalformedOrUnavailableSource() throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([
            fields(["known"]) + Data("unterminated".utf8),
        ])
        let malformed = try discoverySnapshot(fixture, cap: 1)
        let query: ScriptValue = .object(["contains": .string("missing")])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: query, snapshot: malformed)) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("expected refusal") }
            XCTAssertEqual(refusal.code, .malformedInput)
        }
        var unavailable = malformed
        unavailable.mutateAnalysis(in: .primary) { $0.imageBytes = Data() }
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: query, snapshot: unavailable)) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("expected refusal") }
            XCTAssertEqual(refusal.code, .preconditionFailed)
        }
        let page = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "contains": .string("missing"), "page": .bool(true),
        ]), snapshot: unavailable)
        XCTAssertEqual(page["total"], .null)
        XCTAssertEqual(page["sourceComplete"], .bool(false))
    }

    func testDiscoveryContinuesLongFieldWithoutInventingSuffix() throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([
            Data(repeating: 97, count: 1_048_600) + Data([0]) + fields(["needle"]),
        ])
        let snapshot = try discoverySnapshot(fixture, cap: 0)
        let first = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "contains": .string("needle"),
        ]), snapshot: snapshot)
        XCTAssertEqual(try values(first["rows"]), [])
        XCTAssertEqual(first["total"], .null)
        let cursor = try XCTUnwrap(first["nextCursor"])
        let next = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "contains": .string("needle"), "cursor": cursor,
        ]), snapshot: snapshot)
        XCTAssertEqual(try values(next["rows"]), ["needle"])
        XCTAssertEqual(next["total"], .int(1))
    }

    func testDiscoveryCursorRejectsTamperingAndNewGeneration() throws {
        var snapshot = try discoverySnapshot(MachOFixture.makeExecutableWithStringSections([
            fields(["one", "two", "three"]),
        ]), cap: 1)
        let first = try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "limit": .int(1),
        ]), snapshot: snapshot)
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        assertStale { try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "cursor": .string(cursor + "x"),
        ]), snapshot: snapshot) }
        snapshot.mutateAnalysis(in: .primary) { $0.imageBytes.append(0) }
        assertStale { try WorkspaceScriptingAPI.snapshotListRead("strings", arguments: .object([
            "page": .bool(true), "cursor": .string(cursor),
        ]), snapshot: snapshot) }
    }

    // MARK: - E1 evidence-stage cap scenarios (item 1331, ER15)
    // Evidence generation only. No downstream rendering is asserted here.

    /// "old" at 0x2000 is the only persisted row; "txt" sits at 0x2010 in the same
    /// `__TEXT,__cstring` section, past the persisted (capped) evidence.
    private func cappedEvidenceRebuild(referencingTarget: Bool) throws -> (ImageAnalysis, [StringLiteralSummary]) {
        var bytes = Array("old".utf8) + [0]
        bytes += [UInt8](repeating: 0, count: 0x10 - bytes.count)
        bytes += Array("txt".utf8) + [0]
        let data = Data(bytes)
        let section = SectionSummary(id: UUID(), name: "__TEXT,__cstring", address: 0x2000,
            size: UInt64(data.count), fileOffset: 0, isExecutable: false, containsCStringLiterals: true)
        let old = StringLiteralSummary(id: UUID(), value: "old", address: 0x2000,
                                       sourceSection: section.name, byteLength: 3)
        var persisted = ImageAnalysis()
        persisted.stringLiterals = [old]
        persisted.imageBytes = data
        persisted.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        if referencingTarget {
            persisted.xrefs = [XRef(id: UUID(), from: 0x200, to: 0x2010, kind: XRefKind.data)]
        }
        let id = UUID()
        let loader = RehydrationLoaderProducts(requestID: id, requestedSliceIndex: nil,
            imageByteCount: data.count, sliceOffset: 0, sliceSize: UInt64(data.count), sections: [section],
            mappings: FileAddressMapping.verifiedMappings(from: [section], payloadLength: data.count))
        let codec = AnalysisRehydrateWireCodec()
        let decoded = try codec.decodeLoaderReply(codec.encodeLoaderReply(.success(loader)), requestID: id,
            requestImageByteCount: data.count, requestedSliceIndex: nil)
        let result = try RehydrationDerivedProducts.rebuild(persisted: persisted, loader: decoded,
            imageBytes: data, cancellation: .never)
        return (persisted, result.stringLiterals)
    }

    func testUnreferencedStringPastEvidenceCapIsNotRecoveredAndCoverageStaysIncomplete() throws {
        let (persisted, literals) = try cappedEvidenceRebuild(referencingTarget: false)
        XCTAssertEqual(literals.map(\.value), ["old"])
        XCTAssertFalse(literals.contains { $0.address == 0x2010 })
        XCTAssertEqual(persisted.stringLiteralCoverage, .incomplete(.stringCountLimitReached))
    }

    func testReferencedStringPastEvidenceCapIsRecoveredWithExactRow() throws {
        let (persisted, literals) = try cappedEvidenceRebuild(referencingTarget: true)
        let row = try XCTUnwrap(literals.first { $0.address == 0x2010 })
        XCTAssertEqual(row.value, "txt")
        XCTAssertEqual(row.sourceSection, "__TEXT,__cstring")
        XCTAssertEqual(row.byteLength, 3)
        XCTAssertEqual(persisted.stringLiteralCoverage, .incomplete(.stringCountLimitReached))
    }

    private func fields(_ values: [String]) -> Data {
        Data(values.flatMap { Array($0.utf8) + [0] })
    }
    private func repeated(_ count: Int) -> Data {
        Data((0..<count).flatMap { _ in [UInt8(97), 0] })
    }
    private func temporaryFile(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("StringExtractionFixture")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url)
        return url
    }
    private func makeStore(count: Int, value: (Int) -> String = { "row\($0)" }) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.stringLiteralCoverage = .complete
        analysis.stringLiterals = (0..<count).map {
            let text = value($0)
            return StringLiteralSummary(id: UUID(), value: text, address: 0x1000 + UInt64($0 * 4),
                sourceSection: $0.isMultiple(of: 2) ? "__TEXT,__cstring" : "__TEXT,__objc_methname",
                byteLength: text.utf8.count)
        }
        return WorkspaceStore(workspaceName: "878 strings",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }
    private func attached(_ store: WorkspaceStore) -> MCPAttachExecutor {
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        return executor
    }
    private func values(_ rows: ScriptValue?) throws -> [String] {
        try XCTUnwrap(rows?.arrayValue).map { try XCTUnwrap($0["value"]?.stringValue) }
    }
    private func assertStale(_ body: () throws -> ScriptValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            guard case ScriptingError.invalidArgument(let detail) = $0 else {
                return XCTFail("wrong error", file: file, line: line)
            }
            XCTAssertTrue(detail.hasPrefix("staleCursor:"), detail, file: file, line: line)
        }
    }
    private func oversizedSection(_ fixture: MachOFixture, index: Int) -> Data {
        var bytes = fixture.bytes
        let headerSize = 32, segmentHeaderSize = 72, sectionRecordSize = 80
        let record = headerSize + segmentHeaderSize + sectionRecordSize * index
        MachOFixture.writeUInt64LE(&bytes, at: record + 40, value: UInt64.max)
        return bytes
    }

    func testCStringSectionsWinTheBudgetAndStayInLoadOrder() throws {
        let fixture = MachOFixture.makeExecutableWithNamedStringSections([
            (name: "__objc_methname", payload: fields((0..<8).map { "m\($0)" })),
            (name: "__cstring", payload: fields(["AppleSMC", "config.ghostty"])),
        ])
        let parsed = try MachOParser().parse(fixture.bytes, options: MachOParseOptions(maximumStringLiterals: 8))
        XCTAssertEqual(parsed.stringLiterals.map(\.value), (0..<6).map { "m\($0)" } + ["AppleSMC", "config.ghostty"])
        XCTAssertEqual(parsed.stringLiteralCoverage, .incomplete(.stringCountLimitReached))
    }

    func testDefaultCapKeepsSixThousandStrings() throws {
        let parsed = try MachOParser().parse(MachOFixture.makeExecutableWithStringSections([repeated(6_000)]).bytes)
        XCTAssertEqual(parsed.stringLiterals.count, 6_000)
        XCTAssertEqual(parsed.stringLiteralCoverage, .complete)
    }

    func testCapConstantAndOptionDefault() {
        XCTAssertEqual(MachORecoveryLimits.maximumStringLiterals, 262_144)
        XCTAssertEqual(MachOParseOptions().maximumStringLiterals, 262_144)
        XCTAssertEqual(MachOParseOptions.default.maximumStringLiterals, 262_144)
    }

    func testLargeImageCStringsReachableThroughInfoAndStrings() async throws {
        let fixture = MachOFixture.makeExecutableWithNamedStringSections([
            (name: "__objc_methname", payload: fields((0..<6_000).map { "m\($0)" })),
            (name: "__cstring", payload: fields(["AppleSMC", "config.ghostty"])),
        ])
        let parsed = try MachOParser().parse(fixture.bytes)
        let section = try XCTUnwrap(parsed.sections.first { $0.sectionName == "__cstring" })
        let url = try temporaryFile(fixture.bytes)
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let engine = AnalysisEngine()
        let snap = try await engine.openBinary(url: url)
        let owner = WorkspaceStore(workspaceName: "878 loader", snapshot: snap, engine: engine, autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: owner)
        let info = try api.execute("info")
        XCTAssertEqual(info["stringCount"], .int(6_002))
        XCTAssertEqual(info["stringLiteralCoverage"]?["status"], .string("complete"))
        XCTAssertEqual(info["stringCountCapped"], .bool(false))
        let apple = try api.execute("strings", arguments: .object([
            "section": .string("__TEXT,__cstring"), "contains": .string("AppleSMC"),
        ]))
        XCTAssertEqual(apple, .array([.object(["value": .string("AppleSMC"), "address": .hex(section.address)])]))
        let config = try api.execute("strings", arguments: .object(["contains": .string("config.ghostty")]))
        XCTAssertEqual(config, .array([.object(["value": .string("config.ghostty"), "address": .hex(section.address + 9)])]))
        let page = try api.execute("strings", arguments: .object(["page": .bool(true), "section": .string("__TEXT,__cstring")]))
        XCTAssertEqual(page["total"], .int(2))
        let asyncInfo = try await api.executeAsync("info")
        XCTAssertEqual(asyncInfo["stringCountCapped"], .bool(false))
    }

    func testFilteredPagesCountAndContinueOnlyMatches() throws {
        let api = WorkspaceScriptingAPI(store: makeStore(count: 30))
        let first = try api.execute("strings", arguments: .object([
            "page": .bool(true), "limit": .int(5), "contains": .string("ROW1"),
        ]))
        XCTAssertEqual(first["total"], .int(11))
        XCTAssertEqual(try values(first["rows"]), ["row1", "row10", "row11", "row12", "row13"])
        let cursor1 = try XCTUnwrap(first["nextCursor"])
        let second = try api.execute("strings", arguments: .object([
            "page": .bool(true), "limit": .int(5), "contains": .string("row1"), "cursor": cursor1,
        ]))
        XCTAssertEqual(second["total"], .int(11))
        XCTAssertEqual(try values(second["rows"]), ["row14", "row15", "row16", "row17", "row18"])
        let cursor2 = try XCTUnwrap(second["nextCursor"])
        let third = try api.execute("strings", arguments: .object([
            "page": .bool(true), "limit": .int(5), "contains": .string("ROW1"), "cursor": cursor2,
        ]))
        XCTAssertEqual(try values(third["rows"]), ["row19"])
        XCTAssertEqual(third["total"], .int(11))
        XCTAssertEqual(third["nextCursor"], .null)
        XCTAssertEqual(third["isTruncated"], .bool(false))
        let section = try api.execute("strings", arguments: .object(["page": .bool(true), "section": .string("__TEXT,__cstring")]))
        XCTAssertEqual(section["total"], .int(15))
        let both = try api.execute("strings", arguments: .object([
            "page": .bool(true), "section": .string("__TEXT,__cstring"), "contains": .string("row1"),
        ]))
        XCTAssertEqual(both["total"], .int(5))
        XCTAssertEqual(try values(both["rows"]), ["row10", "row12", "row14", "row16", "row18"])
        assertStale { try api.execute("strings", arguments: .object([
            "page": .bool(true), "contains": .string("row2"), "cursor": cursor1,
        ])) }
        assertStale { try api.execute("strings", arguments: .object(["page": .bool(true), "cursor": cursor1])) }
        let plain = try api.execute("strings", arguments: .object(["page": .bool(true), "limit": .int(5)]))
        let plainCursor = try XCTUnwrap(plain["nextCursor"])
        assertStale { try api.execute("strings", arguments: .object([
            "page": .bool(true), "contains": .string("row1"), "cursor": plainCursor,
        ])) }
    }

    func testMCPAdvertisesAndValidatesStringFilters() async throws {
        let strings = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "strings" })
        let functions = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "functions" })
        let schema = HeadlessAutomationAuthority.inputSchema(for: strings)
        let other = HeadlessAutomationAuthority.inputSchema(for: functions)
        for key in ["section", "contains"] {
            XCTAssertEqual(schema["properties"]?[key]?["type"], .string("string"))
            XCTAssertEqual(schema["properties"]?[key]?["minLength"], .int(1))
            XCTAssertEqual(schema["properties"]?[key]?["maxLength"], .int(1_024))
            XCTAssertNil(other["properties"]?[key])
        }
        let api = WorkspaceScriptingAPI(store: makeStore(count: 30))
        let page = try await HeadlessAutomationAuthority.executeAsync(command: "strings",
            arguments: .object(["page": .bool(true), "contains": .string("row1")]), api: api)
        XCTAssertEqual(page["total"], .int(11))
        let appleAPI = WorkspaceScriptingAPI(store: makeStore(count: 1, value: { _ in "AppleSMC" }))
        let args = ScriptValue.object(["section": .string("__TEXT,__cstring"), "contains": .string("AppleSMC")])
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validateDiagnosed(command: "strings", arguments: args))
        let row = try await HeadlessAutomationAuthority.executeAsync(command: "strings", arguments: args, api: appleAPI)
        XCTAssertEqual(row, .array([.object(["value": .string("AppleSMC"), "address": .hex(0x1000)])]))
        for args in [ScriptValue.object(["contains": .int(5)]),
                     .object(["section": .string(String(repeating: "x", count: 1_025))])] {
            XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: "strings", arguments: args)) {
                XCTAssertTrue($0 is ToolArgumentError)
            }
        }
    }

    func testInlineFilterRefusals() throws {
        let api = WorkspaceScriptingAPI(store: makeStore(count: 2))
        for key in ["contains", "section"] {
            for bad in [ScriptValue.string(""), .int(5), .string(String(repeating: "x", count: 1_025)), .null] {
                for paged in [false, true] {
                    var args: [String: ScriptValue] = [key: bad]
                    if paged { args["page"] = .bool(true) }
                    XCTAssertThrowsError(try api.execute("strings", arguments: .object(args))) {
                        XCTAssertEqual($0 as? ScriptingError,
                            .invalidArgument("\(key) must be a non-empty string of at most 1024 UTF-8 bytes"))
                    }
                }
            }
        }
    }

    func testAttachedFilteredReadAppliesDefaultAfterFiltering() async throws {
        let owner = makeStore(count: 2_500)
        let result = try await attached(owner).execute("strings", .object(["contains": .string("row1")]))
        let allMatches = (0..<2_500).map { "row\($0)" }.filter { $0.contains("row1") }
        XCTAssertEqual(allMatches.count, 1_111)
        XCTAssertEqual(try values(result), Array(allMatches.prefix(1_000)))
    }

    func testNewlyReachedMalformedSectionIsSkippedNotThrown() throws {
        let fixture = MachOFixture.makeExecutableWithNamedStringSections([
            (name: "__cstring", payload: repeated(5_999) + fields(["AppleSMC"])),
            (name: "__str1", payload: fields(["x"])),
        ])
        let parsed = try MachOParser().parse(oversizedSection(fixture, index: 2))
        XCTAssertEqual(parsed.stringLiterals.count, 6_000)
        XCTAssertEqual(parsed.stringLiterals.first?.value, "a")
        XCTAssertEqual(parsed.stringLiterals.last?.value, "AppleSMC")
        XCTAssertEqual(parsed.stringLiteralCoverage, .incomplete(.malformedSection))
        XCTAssertLessThan(parsed.stringLiterals.count, MachORecoveryLimits.maximumStringLiterals)
    }

    func testCountStopBehindEarlierUnterminatedStopStillSetsCapped() async throws {
        let fixture = MachOFixture.makeExecutableWithStringSections([Data("tail".utf8), repeated(262_145)])
        let url = try temporaryFile(fixture.bytes)
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let engine = AnalysisEngine()
        let snap = try await engine.openBinary(url: url)
        XCTAssertEqual(snap.stringLiteralCoverage, .incomplete(.unterminatedField))
        let owner = WorkspaceStore(workspaceName: "878 masked count stop", snapshot: snap,
                                   engine: engine, autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: owner)
        let inline = try api.execute("info")
        let asynchronous = try await api.executeAsync("info")
        for info in [inline, asynchronous] {
            XCTAssertEqual(info["stringCount"], .null)
            XCTAssertEqual(info["stringRetainedCount"], .int(262_144))
            XCTAssertEqual(info["stringCountLowerBound"], .int(262_145))
            XCTAssertEqual(info["stringCountExact"], .bool(false))
            XCTAssertEqual(info["stringLiteralCoverage"]?["status"], .string("incomplete"))
            XCTAssertEqual(info["stringLiteralCoverage"]?["stopReason"], .string("unterminatedField"))
            XCTAssertEqual(info["stringCountCapped"], .bool(true))
        }
    }

    func testControlUnfilteredLegacyStringsUnchanged() throws {
        let api = WorkspaceScriptingAPI(store: makeStore(count: 7))
        let expected = (0..<7).map {
            ScriptValue.object(["value": .string("row\($0)"), "address": .hex(0x1000 + UInt64($0 * 4))])
        }
        XCTAssertEqual(try api.execute("strings"), .array(expected))
        XCTAssertEqual(try api.execute("strings", arguments: .object(["limit": .int(3)])), .array(Array(expected.prefix(3))))
    }

    func testControlUnfilteredPageCursorHasFiveFields() throws {
        let api = WorkspaceScriptingAPI(store: makeStore(count: 20))
        let page = try api.execute("strings", arguments: .object(["page": .bool(true), "limit": .int(5)]))
        let token = try XCTUnwrap(page["nextCursor"]?.stringValue)
        let data = try XCTUnwrap(Data(base64Encoded: token))
        let decoded = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertEqual(decoded.split(separator: "|", omittingEmptySubsequences: false).count, 5)
        XCTAssertTrue(decoded.hasPrefix("l1|strings|"))
    }

    func testControlUncappedMixedImageKeepsLoadOrder() throws {
        let fixture = MachOFixture.makeExecutableWithNamedStringSections([
            (name: "__objc_methname", payload: fields(["a", "b"])),
            (name: "__cstring", payload: fields(["c"])),
            (name: "__objc_classname", payload: fields(["d"])),
        ])
        let parsed = try MachOParser().parse(fixture.bytes)
        XCTAssertEqual(parsed.stringLiterals.map(\.value), ["a", "b", "c", "d"])
        XCTAssertEqual(parsed.stringLiterals.map(\.sourceSection),
            ["__TEXT,__objc_methname", "__TEXT,__objc_methname", "__TEXT,__cstring", "__TEXT,__objc_classname"])
        XCTAssertEqual(parsed.stringLiteralCoverage, .complete)
    }

    func testSkippedSectionCoveragePrecedence() throws {
        for count in [8, 9] {
            let fixture = MachOFixture.makeExecutableWithNamedStringSections([
                (name: "__cstring", payload: fields(["bad"])),
                (name: "__str1", payload: repeated(count)),
            ])
            let parsed = try MachOParser().parse(oversizedSection(fixture, index: 1),
                                                 options: MachOParseOptions(maximumStringLiterals: 8))
            XCTAssertEqual(parsed.stringLiterals.count, 8)
            XCTAssertEqual(parsed.stringLiteralCoverage,
                           .incomplete(count == 8 ? .malformedSection : .stringCountLimitReached))
        }
    }

    func testFilterDigestCaseAndEscaping() throws {
        let upper = try WorkspaceScriptingAPI.stringListFilter(.object(["contains": .string("ROW1")]))
        let lower = try WorkspaceScriptingAPI.stringListFilter(.object(["contains": .string("row1")]))
        XCTAssertEqual(upper.digest, lower.digest)
        let slash = try WorkspaceScriptingAPI.stringListFilter(.object(["contains": .string("\\0")]))
        let nul = try WorkspaceScriptingAPI.stringListFilter(.object(["contains": .string("\0")]))
        XCTAssertNotEqual(slash.digest, nul.digest)
    }

    func testFilteredEmptyPageAndLegacyLimitAfterMatching() throws {
        let api = WorkspaceScriptingAPI(store: makeStore(count: 30))
        let page = try api.execute("strings", arguments: .object([
            "page": .bool(true), "contains": .string("absent878"),
        ]))
        XCTAssertEqual(page["rows"], .array([]))
        XCTAssertEqual(page["total"], .int(0))
        XCTAssertEqual(page["isTruncated"], .bool(false))
        XCTAssertEqual(page["nextCursor"], .null)
        let limited = try api.execute("strings", arguments: .object([
            "contains": .string("row1"), "limit": .int(3),
        ]))
        XCTAssertEqual(try values(limited), ["row1", "row10", "row11"])
        XCTAssertEqual(try api.execute("strings", arguments: .object([
            "contains": .string("row1"), "limit": .int(0),
        ])), .array([]))
    }
}
