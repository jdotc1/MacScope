import XCTest
@testable import MacScope

final class PerImagePersistenceTests: XCTestCase {
    private let collidingVA: UInt64 = 0x1_0000_0000

    func testSQLiteRoundTripPreservesPerImageStringCoverage() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var snapshot = twoImageFixture().snapshot
        snapshot.mutateAnalysis(in: .primary) { $0.stringLiteralCoverage = .complete }
        snapshot.mutateAnalysis(in: ImageSlot(rawValue: 7)) {
            $0.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        }
        let workspace = try database.saveSnapshot(workspaceName: "Coverage by image", snapshot: snapshot)
        let restored = try XCTUnwrap(database.loadSnapshot(workspaceID: XCTUnwrap(workspace.id)))
        XCTAssertEqual(restored.analysis(in: .primary)?.stringLiteralCoverage, .complete)
        XCTAssertEqual(restored.analysis(in: ImageSlot(rawValue: 7))?.stringLiteralCoverage,
                       .incomplete(.stringCountLimitReached))
    }

    func testSnapshotSaveRollsBackWhenLiteralWriteFails() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        try database.executeRawForTesting("""
            CREATE TRIGGER reject_literal BEFORE INSERT ON string_literals
            BEGIN SELECT RAISE(ABORT, 'synthetic literal failure'); END;
            """)
        XCTAssertThrowsError(try database.saveSnapshot(workspaceName: "Atomic coverage",
                                                       snapshot: twoImageFixture().snapshot))
        XCTAssertTrue(try database.workspaces().isEmpty)
    }

    func testFailedNestedSnapshotSaveKeepsOwnerTransactionUsable() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        try database.executeRawForTesting("""
            CREATE TRIGGER reject_literal BEFORE INSERT ON string_literals
            BEGIN SELECT RAISE(ABORT, 'synthetic literal failure'); END;
            """)
        try database.withOwnerReplayTransaction {
            XCTAssertThrowsError(try database.saveSnapshot(workspaceName: "Rejected", snapshot: twoImageFixture().snapshot))
            try database.executeRawForTesting("""
                INSERT INTO workspaces (uuid, name, created_at, modified_at)
                VALUES ('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA', 'Owner', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z');
                """)
        }
        XCTAssertEqual(try database.workspaces().map(\.name), ["Owner"])
    }

    func testStringCoverageRoundTripsAllStatesAndUnknown() throws {
        let states: [StringLiteralCoverage?] = [nil, .complete, .notAttempted,
            .incomplete(.stringCountLimitReached), .incomplete(.unterminatedField),
            .incomplete(.malformedSection)]
        for state in states {
            let database = try WorkspaceDatabase.inMemory()
            try database.applySchema()
            var snapshot = twoImageFixture().snapshot
            snapshot.mutateAnalysis(in: .primary) { $0.stringLiteralCoverage = state }
            snapshot.mutateAnalysis(in: ImageSlot(rawValue: 7)) { $0.stringLiteralCoverage = .complete }
            let id = try XCTUnwrap(database.saveSnapshot(workspaceName: "Coverage", snapshot: snapshot).id)
            let loaded = try XCTUnwrap(database.loadSnapshot(workspaceID: id))
            XCTAssertEqual(loaded.analysis(in: .primary)?.stringLiteralCoverage, state)
            XCTAssertEqual(loaded.analysis(in: ImageSlot(rawValue: 7))?.stringLiteralCoverage, .complete)
        }
    }

    func testStringCoverageSurvivesFileReopen() throws {
        let url = temporarySQLiteURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let id: Int64
        do {
            let database = try WorkspaceDatabase(path: url.path)
            try database.applySchema()
            var snapshot = twoImageFixture().snapshot
            snapshot.mutateAnalysis(in: .primary) { $0.stringLiteralCoverage = .complete }
            snapshot.mutateAnalysis(in: ImageSlot(rawValue: 7)) {
                $0.stringLiteralCoverage = .incomplete(.unterminatedField)
            }
            id = try XCTUnwrap(database.saveSnapshot(workspaceName: "File reopen", snapshot: snapshot).id)
        }
        let reopened = try WorkspaceDatabase(path: url.path)
        try reopened.applySchema()
        let snapshot = try XCTUnwrap(reopened.loadSnapshot(workspaceID: id))
        XCTAssertEqual(snapshot.analysis(in: .primary)?.stringLiteralCoverage, .complete)
        XCTAssertEqual(snapshot.analysis(in: ImageSlot(rawValue: 7))?.stringLiteralCoverage,
                       .incomplete(.unterminatedField))
    }

    func testLegacyStringCoverageMigrationDoesNotInventCompleteness() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var snapshot = twoImageFixture().snapshot
        snapshot.mutateAnalysis(in: .primary) { $0.stringLiteralCoverage = .complete }
        let id = try XCTUnwrap(database.saveSnapshot(workspaceName: "Legacy", snapshot: snapshot).id)
        try database.executeRawForTesting("ALTER TABLE binaries DROP COLUMN string_literal_coverage;")
        try database.setUserVersionForTesting(44)
        try database.applySchema()
        XCTAssertEqual(try database.userVersion(), 46)
        let restored = try XCTUnwrap(database.loadSnapshot(workspaceID: id))
        XCTAssertNil(restored.analysis(in: .primary)?.stringLiteralCoverage)
        XCTAssertEqual(restored.analysis(in: .primary)?.stringLiterals,
                       snapshot.analysis(in: .primary)?.stringLiterals)
    }

    func testLegacySidecarPreflightPreservesIdentityBeforeCoverageMigration() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let workspaceID = UUID(), documentID = UUID()
        let path = "/synthetic/Coverage.mscope"
        let rowID = try database.bootstrapReconstructionWorkspaceSidecar(
            workspaceUUID: workspaceID, workspaceName: "Coverage", documentID: documentID,
            canonicalPackagePath: path, now: Date(timeIntervalSince1970: 1_800_000_000))
        try database.executeRawForTesting("ALTER TABLE binaries DROP COLUMN string_literal_coverage;")
        try database.setUserVersionForTesting(44)
        XCTAssertEqual(try database.preflightReconstructionSidecarBindingBeforeMigration(
            workspaceUUID: workspaceID, documentID: documentID, canonicalPackagePath: path),
                       .matched(workspaceRowID: rowID))
        XCTAssertEqual(try database.preflightReconstructionSidecarBindingBeforeMigration(
            workspaceUUID: workspaceID, documentID: UUID(), canonicalPackagePath: path), .documentMismatch)
        XCTAssertEqual(try database.userVersion(), 44)
        try database.applySchema()
        XCTAssertEqual(try database.userVersion(), 46)
    }

    func testStringCoverageMigrationRollsBackOnInvalidLaterSchema() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        try database.executeRawForTesting("ALTER TABLE binaries DROP COLUMN string_literal_coverage;")
        try database.executeRawForTesting("ALTER TABLE instructions RENAME COLUMN structured_operands_json TO broken_operands;")
        try database.setUserVersionForTesting(44)
        XCTAssertThrowsError(try database.applySchema())
        XCTAssertEqual(try database.userVersion(), 44)
        XCTAssertFalse(try database.columnNames(in: "binaries").contains("string_literal_coverage"))
    }

    func testStringCoverageRejectsSchemaWithFabricatedDefault() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        try database.executeRawForTesting("ALTER TABLE binaries DROP COLUMN string_literal_coverage;")
        try database.executeRawForTesting("ALTER TABLE binaries ADD COLUMN string_literal_coverage TEXT DEFAULT 'complete';")
        try database.setUserVersionForTesting(44)
        XCTAssertThrowsError(try database.applySchema())
        XCTAssertEqual(try database.userVersion(), 44)
    }

    func testCurrentSchemaRejectsMissingCoverageColumn() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        try database.executeRawForTesting("ALTER TABLE binaries DROP COLUMN string_literal_coverage;")
        XCTAssertThrowsError(try database.applySchema())
        XCTAssertEqual(try database.userVersion(), 46)
        XCTAssertFalse(try database.columnNames(in: "binaries").contains("string_literal_coverage"))
    }

    func testStringCoverageRejectsMalformedStoredTokens() throws {
        for value in ["'unknown'", "'incomplete:future'", "zeroblob(8)",
                      "CAST(X'636f6d706c65746500626164' AS TEXT)", "CAST(X'ff' AS TEXT)"] {
            let database = try WorkspaceDatabase.inMemory()
            try database.applySchema()
            let id = try XCTUnwrap(database.saveSnapshot(workspaceName: "Corrupt", snapshot: twoImageFixture().snapshot).id)
            try database.executeRawForTesting("UPDATE binaries SET string_literal_coverage = \(value);")
            XCTAssertThrowsError(try database.loadSnapshot(workspaceID: id), "Accepted malformed value \(value)")
        }
    }

    func testConcurrentReplacementCannotMixCoverageRowsAndPackageBytes() throws {
        for route in 0..<3 {
            let url = temporarySQLiteURL()
            defer {
                try? FileManager.default.removeItem(at: url)
                try? FileManager.default.removeItem(atPath: url.path + "-wal")
                try? FileManager.default.removeItem(atPath: url.path + "-shm")
            }
            let reader = try WorkspaceDatabase(path: url.path)
            try reader.applySchema()
            try reader.executeRawForTesting("PRAGMA journal_mode = WAL;")
            var original = twoImageFixture().snapshot
            original.mutateAnalysis(in: .primary) { $0.stringLiteralCoverage = .complete }
            let id = try XCTUnwrap(reader.saveSnapshot(workspaceName: "Generation", snapshot: original).id)
            let writer = try WorkspaceDatabase(path: url.path)
            try writer.applySchema()
            var replacement = original
            replacement.mutateAnalysis(in: .primary) {
                $0.stringLiteralCoverage = .incomplete(.malformedSection)
                $0.stringLiterals[0].value = "replacement"
                $0.imageBytes = Data([1, 2, 3, 4, 5])
            }
            var fired = false
            reader.setCoverageReadHookForTesting(route == 2 ? .afterPackageSnapshot : .afterBinaryRows) {
                fired = true
                _ = try writer.replaceWorkspaceState(workspaceID: id, workspaceName: "Generation",
                    snapshot: replacement, selectedSidebarItemID: nil, selectedAddress: nil,
                    selectedTool: .project, editorMode: .disassembly, isInspectorPresented: true,
                    sidebarSearchText: "")
            }
            if route == 2 {
                let package = try reader.packageComponents(workspaceID: id, documentID: UUID(),
                    inputCopyingDecision: .copyInputsIntoPackage,
                    bookmarkResolutionDecision: .resolveStoredBookmarks, phase2ShellSession: nil)
                let primary = try XCTUnwrap(package.manifest.imageAnalyses?.first { $0.imageSlot == .primary })
                XCTAssertEqual(primary.analysis.stringLiteralCoverage, .complete)
                XCTAssertEqual(primary.analysis.stringLiterals, original.analysis(in: .primary)?.stringLiterals)
                let binaryID = try XCTUnwrap(original.binary(in: .primary)?.id)
                XCTAssertEqual(package.attachmentsByBinaryID[binaryID], original.analysis(in: .primary)?.imageBytes)
            } else {
                let captured = try XCTUnwrap(route == 0 ? reader.loadSnapshot(workspaceID: id)
                    : reader.loadWorkspaceState(workspaceID: id)?.snapshot)
                XCTAssertEqual(captured.analysis(in: .primary)?.stringLiteralCoverage, .complete)
                XCTAssertEqual(captured.analysis(in: .primary)?.stringLiterals,
                               original.analysis(in: .primary)?.stringLiterals)
            }
            XCTAssertTrue(fired)
            let latest = try XCTUnwrap(reader.loadSnapshot(workspaceID: id))
            XCTAssertEqual(latest.analysis(in: .primary)?.stringLiteralCoverage, .incomplete(.malformedSection))
            XCTAssertEqual(latest.analysis(in: .primary)?.stringLiterals.first?.value, "replacement")
        }
    }

    func testSQLiteRoundTripKeepsCollidingImagesInDistinctBinaryBuckets() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let fixture = twoImageFixture()

        let workspace = try database.saveSnapshot(
            workspaceName: "Per-image SQLite",
            snapshot: fixture.snapshot,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let workspaceID = try XCTUnwrap(workspace.id)
        let binaryRows = try database.binaries(workspaceID: workspaceID)

        XCTAssertEqual(binaryRows.map(\.imageSlot), [0, 7])
        XCTAssertEqual(binaryRows.map(\.hexBytes), [fixture.primaryBytes, fixture.siblingBytes])

        let primaryBinaryID = try XCTUnwrap(binaryRows[0].id)
        let siblingBinaryID = try XCTUnwrap(binaryRows[1].id)
        XCTAssertEqual(try database.functions(binaryID: primaryBinaryID).map(\.uuid), [fixture.primaryFunctionID])
        XCTAssertEqual(try database.functions(binaryID: siblingBinaryID).map(\.uuid), [fixture.siblingFunctionID])
        XCTAssertEqual(try database.symbols(binaryID: primaryBinaryID).map(\.name), ["_primary_symbol"])
        XCTAssertEqual(try database.symbols(binaryID: siblingBinaryID).map(\.name), ["_sibling_symbol"])
        XCTAssertEqual(try database.imports(binaryID: primaryBinaryID).map(\.name), ["_primary_import"])
        XCTAssertEqual(try database.imports(binaryID: siblingBinaryID).map(\.name), ["_sibling_import"])
        XCTAssertEqual(try database.indirectSymbols(binaryID: primaryBinaryID).map(\.symbolName), ["_primary_import"])
        XCTAssertEqual(try database.indirectSymbols(binaryID: siblingBinaryID).map(\.symbolName), ["_sibling_import"])
        XCTAssertEqual(try database.exports(binaryID: primaryBinaryID).map(\.name), ["_primary_export"])
        XCTAssertEqual(try database.exports(binaryID: siblingBinaryID).map(\.name), ["_sibling_export"])
        XCTAssertEqual(try database.stringLiterals(binaryID: primaryBinaryID).map(\.value), ["primary-string"])
        XCTAssertEqual(try database.stringLiterals(binaryID: siblingBinaryID).map(\.value), ["sibling-string"])
        XCTAssertEqual(try database.xrefs(binaryID: primaryBinaryID).map(\.kind), ["primary_call"])
        XCTAssertEqual(try database.xrefs(binaryID: siblingBinaryID).map(\.kind), ["sibling_call"])
        XCTAssertEqual(try database.controlFlowEdges(binaryID: primaryBinaryID).map(\.kind), ["primary_fallthrough"])
        XCTAssertEqual(try database.controlFlowEdges(binaryID: siblingBinaryID).map(\.kind), ["sibling_fallthrough"])

        let primaryFunctionRowID = try XCTUnwrap(try database.functions(binaryID: primaryBinaryID).first?.id)
        let siblingFunctionRowID = try XCTUnwrap(try database.functions(binaryID: siblingBinaryID).first?.id)
        XCTAssertEqual(try database.instructions(functionID: primaryFunctionRowID).map(\.mnemonic), ["primary_ret"])
        XCTAssertEqual(try database.instructions(functionID: siblingFunctionRowID).map(\.mnemonic), ["sibling_ret"])
        XCTAssertEqual(try database.basicBlocks(functionID: primaryFunctionRowID).map(\.functionID), [primaryFunctionRowID])
        XCTAssertEqual(try database.basicBlocks(functionID: siblingFunctionRowID).map(\.functionID), [siblingFunctionRowID])

        let reopened = try XCTUnwrap(database.loadSnapshot(workspaceID: workspaceID))
        XCTAssertEqual(reopened.binaries.map(\.slot), [.primary, ImageSlot(rawValue: 7)])
        XCTAssertEqual(reopened.analysis(in: .primary)?.functions.map(\.id), [fixture.primaryFunctionID])
        XCTAssertEqual(reopened.analysis(in: ImageSlot(rawValue: 7))?.functions.map(\.id), [fixture.siblingFunctionID])
        XCTAssertEqual(reopened.analysis(in: .primary)?.imports.map(\.name), ["_primary_import"])
        XCTAssertEqual(reopened.analysis(in: ImageSlot(rawValue: 7))?.imports.map(\.name), ["_sibling_import"])
        XCTAssertEqual(reopened.analysis(in: .primary)?.instructions.map(\.mnemonic), ["primary_ret"])
        XCTAssertEqual(reopened.analysis(in: ImageSlot(rawValue: 7))?.instructions.map(\.mnemonic), ["sibling_ret"])
        XCTAssertEqual(reopened.analysis(in: .primary)?.imageBytes, fixture.primaryBytes)
        XCTAssertEqual(reopened.analysis(in: ImageSlot(rawValue: 7))?.imageBytes, fixture.siblingBytes)
        XCTAssertEqual(
            reopened.analysis(in: .primary)?.hexBytes,
            Data(fixture.primaryBytes.prefix(WorkspaceSnapshot.hexViewByteWindow))
        )
        XCTAssertEqual(
            reopened.analysis(in: ImageSlot(rawValue: 7))?.hexBytes,
            Data(fixture.siblingBytes.prefix(WorkspaceSnapshot.hexViewByteWindow))
        )
    }

    func testInPlaceResaveKeepsEveryImagesRowsAndReplacementBytes() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let fixture = twoImageFixture()
        let initial = try database.saveWorkspaceState(
            workspaceName: "In-place",
            snapshot: fixture.snapshot,
            selectedSidebarItemID: nil,
            selectedAddress: collidingVA,
            selectedTool: .project,
            editorMode: .disassembly,
            isInspectorPresented: true,
            sidebarSearchText: ""
        )
        let workspaceID = try XCTUnwrap(initial.workspace.id)

        let replacementPrimary = Data([0xaa, 0xbb, 0xcc])
        let replacementSibling = Data([0x77, 0x88, 0x99, 0xaa])
        var replacement = fixture.snapshot
        replacement.mutateAnalysis(in: .primary) {
            $0.imageBytes = replacementPrimary
            $0.hexBytes = replacementPrimary
            $0.functions[0].name = "primary_replaced"
        }
        replacement.mutateAnalysis(in: ImageSlot(rawValue: 7)) {
            $0.imageBytes = replacementSibling
            $0.hexBytes = replacementSibling
            $0.functions[0].name = "sibling_replaced"
        }

        _ = try database.replaceWorkspaceState(
            workspaceID: workspaceID,
            workspaceName: "In-place",
            snapshot: replacement,
            selectedSidebarItemID: nil,
            selectedAddress: collidingVA,
            selectedTool: .project,
            editorMode: .disassembly,
            isInspectorPresented: true,
            sidebarSearchText: ""
        )

        let rows = try database.binaries(workspaceID: workspaceID)
        XCTAssertEqual(rows.map(\.hexBytes), [replacementPrimary, replacementSibling])
        let reopened = try XCTUnwrap(database.loadSnapshot(workspaceID: workspaceID))
        XCTAssertEqual(reopened.analysis(in: .primary)?.functions.first?.name, "primary_replaced")
        XCTAssertEqual(reopened.analysis(in: ImageSlot(rawValue: 7))?.functions.first?.name, "sibling_replaced")
        XCTAssertEqual(reopened.analysis(in: .primary)?.imageBytes, replacementPrimary)
        XCTAssertEqual(reopened.analysis(in: ImageSlot(rawValue: 7))?.imageBytes, replacementSibling)
    }

    func testSQLiteSaveUsesEachImagesHexPrefixWhenImageBytesIsEmpty() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var snapshot = twoImageFixture().snapshot
        let primaryFallback = Data([0x10, 0x11])
        let siblingFallback = Data([0x70, 0x71, 0x72])
        snapshot.mutateAnalysis(in: .primary) {
            $0.imageBytes = Data()
            $0.hexBytes = primaryFallback
        }
        snapshot.mutateAnalysis(in: ImageSlot(rawValue: 7)) {
            $0.imageBytes = Data()
            $0.hexBytes = siblingFallback
        }

        let workspace = try database.saveSnapshot(workspaceName: "Hex fallback", snapshot: snapshot)
        XCTAssertEqual(
            try database.binaries(workspaceID: try XCTUnwrap(workspace.id)).map(\.hexBytes),
            [primaryFallback, siblingFallback]
        )
    }

    /// A binary WITHOUT an analysis bucket is a valid snapshot — the compat init routes derived data
    /// only to the primary slot, and `WorkspaceSnapshot.validateInvariants()` permits bucketless
    /// binaries. Saving one must succeed (persisting an empty image), not throw: derived data is
    /// recomputed on reanalysis, so an empty persisted bucket is lossless (it matches the existing
    /// "reloaded snapshot has empty derived tables until reanalysis" behavior).
    /// WS-5: dSYM source lines are not byte-derivable, so they must survive save/reopen through the
    /// new per-binary_id source_lines table — including a nil `file` and the end-sequence flag.
    func testSourceLinesRoundTripThroughDatabase() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let binary = BinaryImage(id: UUID(), name: "sl", path: "/tmp/sl",
                                 kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        var analysis = ImageAnalysis()
        analysis.functions = [FunctionSummary(id: UUID(), name: "fn", startAddress: 0x1000, endAddress: 0x1010, confidence: 1)]
        analysis.sourceLines = [
            SourceLineEntry(address: 0x1000, file: "/src/main.c", line: 42, column: 3, endSequence: false),
            SourceLineEntry(address: 0x1008, file: nil, line: 43, column: 0, endSequence: true),
        ]
        analysis.analysisInputFingerprint = try analysisFingerprint(
            binaryID: binary.id,
            slot: .primary,
            overallSHA256: String(repeating: "a", count: 64)
        )
        let snapshot = WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
        let workspace = try database.saveSnapshot(workspaceName: "SL", snapshot: snapshot)
        let reloaded = try XCTUnwrap(try database.loadSnapshot(workspaceID: try XCTUnwrap(workspace.id)))
        XCTAssertEqual(reloaded.analysis(in: .primary)?.sourceLines, analysis.sourceLines)
        XCTAssertEqual(
            reloaded.analysis(in: .primary)?.analysisInputFingerprint,
            analysis.analysisInputFingerprint
        )
    }

    /// WS-5: source lines round-trip through the .mscope analysis record (both v1 flat and v2
    /// per-image use `WorkspacePackageAnalysis`), and an older package with no `sourceLines` key
    /// decodes as empty (additive key, no format bump).
    func testPackageAnalysisSourceLinesCodableRoundTripAndLegacyDefault() throws {
        var image = ImageAnalysis()
        image.sourceLines = [
            SourceLineEntry(address: 0x1000, file: "/a.c", line: 5, column: 2, endSequence: false),
            SourceLineEntry(address: 0x1004, file: nil, line: 6, column: 0, endSequence: true),
        ]
        image.analysisInputFingerprint = try analysisFingerprint(
            binaryID: UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!,
            slot: .primary,
            overallSHA256: String(repeating: "b", count: 64)
        )
        let analysis = WorkspacePackageAnalysis(imageAnalysis: image)
        let data = try JSONEncoder().encode(analysis)
        let decoded = try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: data)
        XCTAssertEqual(decoded.sourceLines, image.sourceLines)
        XCTAssertEqual(decoded.analysisInputFingerprint, image.analysisInputFingerprint)

        // Legacy package (pre-WS-5/fingerprint persistence) has no additive keys → decodes empty/nil, no bump.
        let legacy = try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: Data("{}".utf8))
        XCTAssertTrue(legacy.sourceLines.isEmpty)
        XCTAssertNil(legacy.analysisInputFingerprint)
    }

    func testSQLiteSaveToleratesBinaryWithoutAnalysisBucketAsEmptyImage() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let missingSlot = ImageSlot(rawValue: 7)
        let snapshot = WorkspaceSnapshot(
            binaries: [
                BinaryImage(
                    id: UUID(),
                    name: "missing-analysis",
                    path: "/missing/analysis",
                    kind: "Mach-O executable",
                    architecture: "arm64",
                    slot: missingSlot
                )
            ],
            analysisBySlot: [:]
        )

        let persisted = try database.saveWorkspaceState(
            workspaceName: "Missing analysis",
            snapshot: snapshot,
            selectedSidebarItemID: nil,
            selectedAddress: nil,
            selectedTool: .project,
            editorMode: .disassembly,
            isInspectorPresented: true,
            sidebarSearchText: ""
        )
        let reloaded = try XCTUnwrap(try database.loadSnapshot(workspaceID: try XCTUnwrap(persisted.workspace.id)))
        XCTAssertEqual(reloaded.binary(in: missingSlot)?.slot, missingSlot)
        XCTAssertEqual(reloaded.analysis(in: missingSlot)?.functions.count ?? 0, 0)
        XCTAssertEqual(reloaded.analysis(in: missingSlot)?.instructions.count ?? 0, 0)
    }

    func testSchemaV27AddsBinarySlotUniquenessAndFocusedSessionSlot() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()

        XCTAssertEqual(try database.userVersion(), WorkspaceDatabase.schemaVersion)
        XCTAssertEqual(
            try database.indexColumns(of: "idx_binaries_workspace_image_slot"),
            ["workspace_id", "image_slot"]
        )
        XCTAssertTrue(try database.columnNames(in: "workspace_sessions").contains("focused_image_slot"))
    }

    func testFocusedImageSlotPersistsThroughWorkspaceStateAndFileReopen() throws {
        let databaseURL = temporarySQLiteURL()
        defer { try? FileManager.default.removeItem(at: databaseURL) }
        let fixture = twoImageFixture()
        let focusedSlot = ImageSlot(rawValue: 7)
        let workspaceID: Int64

        do {
            let database = try WorkspaceDatabase(path: databaseURL.path)
            try database.applySchema()
            let state = try database.saveWorkspaceState(
                workspaceName: "Focused slot",
                snapshot: fixture.snapshot,
                selectedSidebarItemID: "binary:\(fixture.snapshot.binaries[1].id.uuidString)",
                selectedAddress: collidingVA,
                selectedTool: .project,
                editorMode: .disassembly,
                isInspectorPresented: true,
                sidebarSearchText: "",
                focusedImageSlot: focusedSlot
            )
            workspaceID = try XCTUnwrap(state.workspace.id)
            XCTAssertEqual(state.session.focusedImageSlot, focusedSlot)
        }

        let reopened = try WorkspaceDatabase(path: databaseURL.path)
        try reopened.applySchema()
        let state = try XCTUnwrap(reopened.loadWorkspaceState(workspaceID: workspaceID))
        XCTAssertEqual(state.session.focusedImageSlot, focusedSlot)
    }

    func testVersion26MigrationPreservesPrimaryPayloadSlotAndSliceAndIsIdempotent() throws {
        let databaseURL = temporarySQLiteURL()
        defer { try? FileManager.default.removeItem(at: databaseURL) }
        let payload = Data((0..<5_000).map { UInt8(truncatingIfNeeded: $0) })
        let binaryID = UUID(uuidString: "26000000-0000-0000-0000-000000000026")!
        let workspaceID: Int64

        do {
            let database = try WorkspaceDatabase(path: databaseURL.path)
            try database.applySchema()
            let snapshot = WorkspaceSnapshot(
                binaries: [
                    BinaryImage(
                        id: binaryID,
                        name: "v26-primary",
                        path: "/missing/v26-primary",
                        kind: "Mach-O executable",
                        architecture: "arm64",
                        selectedSliceIndex: 3,
                        slot: .primary
                    )
                ],
                analysisBySlot: [
                    .primary: ImageAnalysis(
                        hexBytes: Data(payload.prefix(WorkspaceSnapshot.hexViewByteWindow)),
                        imageBytes: payload
                    )
                ]
            )
            workspaceID = try XCTUnwrap(
                try database.saveWorkspaceState(
                    workspaceName: "v26 migration",
                    snapshot: snapshot,
                    selectedSidebarItemID: "binary:\(binaryID.uuidString)",
                    selectedAddress: nil,
                    selectedTool: .project,
                    editorMode: .disassembly,
                    isInspectorPresented: true,
                    sidebarSearchText: ""
                ).workspace.id
            )
            try database.executeRawForTesting("""
                DROP INDEX idx_binaries_workspace_image_slot;
                ALTER TABLE workspace_sessions DROP COLUMN focused_image_slot;
                PRAGMA user_version = 26;
                """)
        }

        let migrated = try WorkspaceDatabase(path: databaseURL.path)
        try migrated.applySchema()
        XCTAssertEqual(try migrated.userVersion(), WorkspaceDatabase.schemaVersion)
        let binary = try XCTUnwrap(try migrated.binaries(workspaceID: workspaceID).first)
        XCTAssertEqual(binary.uuid, binaryID)
        XCTAssertEqual(binary.imageSlot, 0)
        XCTAssertEqual(binary.selectedSliceIndex, 3)
        XCTAssertEqual(binary.hexBytes, payload)
        XCTAssertEqual(try migrated.workspaceSession(workspaceID: workspaceID)?.focusedImageSlot, .primary)

        // Re-entering the v26 migration after the wide index and column already exist proves the
        // DROP-before-CREATE helper is idempotent and cannot resurrect an obsolete index shape.
        try migrated.setUserVersionForTesting(26)
        try migrated.applySchema()
        XCTAssertEqual(try migrated.userVersion(), WorkspaceDatabase.schemaVersion)
        XCTAssertEqual(
            try migrated.indexColumns(of: "idx_binaries_workspace_image_slot"),
            ["workspace_id", "image_slot"]
        )
        XCTAssertEqual(try migrated.binaries(workspaceID: workspaceID).first?.hexBytes, payload)
    }

    func testVersion26MigrationRejectsDuplicateBinarySlotsWithClearDiagnostic() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let workspace = try database.insertWorkspace(
            WorkspaceDatabase.WorkspaceRecord(
                id: nil,
                uuid: UUID(),
                name: "duplicate slots",
                createdAt: Date(timeIntervalSince1970: 1_800_000_000),
                modifiedAt: Date(timeIntervalSince1970: 1_800_000_000)
            )
        )
        let workspaceID = try XCTUnwrap(workspace.id)
        try database.executeRawForTesting("DROP INDEX idx_binaries_workspace_image_slot;")
        for offset in 0..<2 {
            _ = try database.insertBinary(
                WorkspaceDatabase.BinaryRecord(
                    id: nil,
                    uuid: UUID(),
                    workspaceID: workspaceID,
                    name: "duplicate-\(offset)",
                    path: "/missing/duplicate-\(offset)",
                    originalPathBookmark: nil,
                    kind: "Mach-O executable",
                    architecture: "arm64",
                    fileHash: "",
                    fileSize: 1,
                    hexBytes: Data([UInt8(offset)]),
                    isBundle: false,
                    imageSlot: 7,
                    selectedSliceIndex: nil
                )
            )
        }
        try database.setUserVersionForTesting(26)

        XCTAssertThrowsError(try database.applySchema()) { error in
            XCTAssertEqual(
                error as? WorkspaceDatabase.DatabaseError,
                .duplicateImageSlot(workspaceID: workspaceID, imageSlot: 7)
            )
            XCTAssertTrue(error.localizedDescription.contains("Workspace \(workspaceID)"))
            XCTAssertTrue(error.localizedDescription.contains("slot 7"))
        }
        XCTAssertEqual(try database.userVersion(), 26)
        XCTAssertEqual(try database.binaries(workspaceID: workspaceID).map(\.imageSlot), [7, 7])
    }

    func testWorkspacePackageBinarySlotUsesLegacyOmissionAndMissingKeyDefault() throws {
        let data = Data([0xca, 0xfe])
        let primary = packageBinary(
            id: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
            slot: .primary,
            data: data
        )
        let primaryObject = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(primary)) as? [String: Any]
        )
        XCTAssertNil(primaryObject["slot"], "primary slot must be omitted from legacy v1 bytes")

        let legacyJSON = Data("""
        {
          "id": "20000000-0000-0000-0000-000000000002",
          "displayName": "legacy",
          "originalPath": "/tmp/legacy",
          "attachmentRelativePath": "attachments/20000000-0000-0000-0000-000000000002/legacy",
          "kind": "Mach-O executable",
          "architecture": "arm64",
          "fileHash": "",
          "fileSize": 2
        }
        """.utf8)
        XCTAssertEqual(try JSONDecoder().decode(WorkspacePackageBinary.self, from: legacyJSON).slot, .primary)

        let sibling = packageBinary(
            id: UUID(uuidString: "70000000-0000-0000-0000-000000000007")!,
            slot: ImageSlot(rawValue: 7),
            data: data
        )
        XCTAssertEqual(
            try JSONDecoder().decode(WorkspacePackageBinary.self, from: JSONEncoder().encode(sibling)).slot,
            ImageSlot(rawValue: 7)
        )
    }

    func testLegacyVersion1PackageOpensIntoOnePrimaryBucketWithExactBytes() throws {
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }
        let binaryID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let functionID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let attachment = Data([0xca, 0xfe, 0xba, 0xbe])
        let relativePath = "attachments/\(binaryID.uuidString.lowercased())/legacy.bin"
        let manifest = """
        {
          "formatIdentifier": "\(MacScopeDocumentPackage.formatIdentifier)",
          "formatVersion": 1,
          "documentID": "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD",
          "workspaceUUID": "11111111-1111-1111-1111-111111111111",
          "workspaceName": "Legacy V1",
          "createdAt": "2027-01-15T08:00:00.000Z",
          "modifiedAt": "2027-01-15T08:00:01.000Z",
          "binaries": [{
            "id": "\(binaryID.uuidString)",
            "displayName": "legacy",
            "originalPath": "/tmp/legacy.bin",
            "attachmentRelativePath": "\(relativePath)",
            "kind": "synthetic fixture",
            "architecture": "arm64",
            "fileHash": "",
            "fileSize": \(attachment.count)
          }],
          "analysis": {
            "functions": [{
              "id": "\(functionID.uuidString)",
              "name": "legacy_function",
              "startAddress": \(collidingVA),
              "endAddress": \(collidingVA + 4),
              "confidence": 1.0
            }]
          }
        }
        """
        try FileManager.default.createDirectory(
            at: packageURL.appendingPathComponent(relativePath).deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(manifest.utf8).write(to: MacScopeDocumentPackage.manifestURL(in: packageURL))
        try attachment.write(to: packageURL.appendingPathComponent(relativePath))

        let opened = try MacScopeDocumentPackage.openPackage(from: packageURL)
        XCTAssertEqual(opened.manifest.formatVersion, 1)
        XCTAssertEqual(opened.snapshot.binaries.map(\.slot), [.primary])
        XCTAssertEqual(Set(opened.snapshot.analysisBySlot.keys), [.primary])
        XCTAssertEqual(opened.snapshot.analysis(in: .primary)?.functions.map(\.id), [functionID])
        XCTAssertEqual(opened.snapshot.analysis(in: .primary)?.imageBytes, attachment)
        XCTAssertEqual(opened.snapshot.analysis(in: .primary)?.hexBytes, attachment)
    }

    func testSinglePrimaryManifestWritesExactLegacyVersion1Bytes() throws {
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let binaryID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let functionID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let timestamp = Date(timeIntervalSince1970: 1_800_000_000)
        let payload = Data([0xca, 0xfe, 0xba, 0xbe])
        let snapshot = WorkspaceSnapshot(
            binaries: [
                BinaryImage(
                    id: binaryID,
                    name: "legacy",
                    path: "/tmp/legacy.bin",
                    kind: "synthetic fixture",
                    architecture: "arm64",
                    selectedSliceIndex: 2,
                    slot: .primary
                )
            ],
            analysisBySlot: [
                .primary: ImageAnalysis(
                    functions: [
                        FunctionSummary(
                            id: functionID,
                            name: "legacy_function",
                            startAddress: collidingVA,
                            endAddress: collidingVA + 4,
                            confidence: 1
                        )
                    ],
                    hexBytes: payload,
                    imageBytes: payload
                )
            ],
            addressOverrides: [
                .primary(collidingVA): AddressOverride(customName: "legacy_name")
            ]
        )
        let state = try database.saveWorkspaceState(
            workspaceName: "Legacy Production V1",
            snapshot: snapshot,
            selectedSidebarItemID: "function:\(functionID.uuidString)",
            selectedAddress: collidingVA,
            selectedTool: .symbols,
            editorMode: .graph,
            isInspectorPresented: false,
            sidebarSearchText: "_legacy",
            now: timestamp
        )
        var manifest = try XCTUnwrap(
            database.packageManifest(
                workspaceID: try XCTUnwrap(state.workspace.id),
                documentID: UUID(uuidString: "dddddddd-dddd-dddd-dddd-dddddddddddd")!
            )
        )
        // The production writer creates the workspace UUID. Pin that one nondeterministic value so
        // the emitted bytes can be compared with the manifest generated by the Phase-2 base SHA.
        manifest.workspaceUUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        // HS-2 (#293) stamps every saved manifest with the analyzer version; the pre-Phase-3 anchor
        // predates the stamp, so compare the remaining bytes (the stamp has its own tests).
        XCTAssertEqual(manifest.analyzer, .current)
        manifest.analyzer = nil

        try MacScopeDocumentPackage.writeManifest(manifest, to: packageURL)
        let actual = try Data(contentsOf: MacScopeDocumentPackage.manifestURL(in: packageURL))
        XCTAssertEqual(actual, prePhase3ProductionVersion1ManifestBytes())
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: actual) as? [String: Any])
        XCTAssertEqual(object["formatVersion"] as? Int, 1)
        XCTAssertNil(object["imageAnalyses"])
        XCTAssertNil((object["binaries"] as? [[String: Any]])?.first?["slot"])
    }

    func testMultiImagePackageWritesVersion2SlotSortedAndRoundTripsAnalysisAuthoringFocusAndBytes() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let fixture = twoImageFixture()
        let siblingSlot = ImageSlot(rawValue: 7)
        var snapshot = fixture.snapshot
        snapshot.addressOverrides = [
            .primary(collidingVA): AddressOverride(customName: "primary_name"),
            ImageAddress(slot: siblingSlot, address: collidingVA): AddressOverride(customName: "sibling_name")
        ]
        snapshot.manualXRefs = [
            ManualXRef(from: collidingVA, to: collidingVA + 4, kind: "manual", isSuppression: false, imageSlot: siblingSlot)
        ]
        snapshot.bookmarks = [
            Bookmark(address: collidingVA, imageSlot: siblingSlot, name: "sibling bookmark")
        ]
        snapshot.segmentOverrides = [
            SegmentOverride(originalName: "__TEXT", imageSlot: siblingSlot, displayName: "Sibling Text")
        ]
        let state = try database.saveWorkspaceState(
            workspaceName: "Package v2",
            snapshot: snapshot,
            selectedSidebarItemID: "binary:\(snapshot.binaries[1].id.uuidString)",
            selectedAddress: collidingVA,
            selectedTool: .project,
            editorMode: .disassembly,
            isInspectorPresented: true,
            sidebarSearchText: "",
            focusedImageSlot: siblingSlot,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let workspaceID = try XCTUnwrap(state.workspace.id)
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }

        let manifest = try database.writePackage(
            workspaceID: workspaceID,
            documentID: UUID(uuidString: "dddddddd-dddd-dddd-dddd-dddddddddddd")!,
            to: packageURL
        )
        // writePackage returns the v4 manifest it wrote; its analysis layout is still v2.
        XCTAssertEqual(manifest.formatVersion, WorkspacePackageManifest.instructionSidecarFormatVersion)
        XCTAssertEqual(manifest.analysisFormatVersion, 2)
        XCTAssertEqual(manifest.binaries.map(\.slot), [.primary, siblingSlot])
        let imageAnalyses = try XCTUnwrap(manifest.imageAnalyses)
        XCTAssertEqual(imageAnalyses.map(\.imageSlot), [.primary, siblingSlot])
        XCTAssertEqual(imageAnalyses.map(\.binaryID), manifest.binaries.map(\.id))
        XCTAssertEqual(imageAnalyses[0].analysis.functions.map(\.id), [fixture.primaryFunctionID])
        XCTAssertEqual(imageAnalyses[1].analysis.functions.map(\.id), [fixture.siblingFunctionID])
        XCTAssertEqual(manifest.analysis?.functions, [], "v2 top-level analysis is authoring-only")
        XCTAssertEqual(manifest.analysis?.addressOverrides.count, 2)
        XCTAssertTrue(imageAnalyses.allSatisfy { $0.analysis.addressOverrides.isEmpty })
        XCTAssertEqual(manifest.session?.focusedImageSlot, siblingSlot)
        XCTAssertEqual(manifest.session?.selectedAddress, collidingVA)
        XCTAssertEqual(
            manifest.session?.selectedSidebarItemID,
            "binary:\(snapshot.binaries[1].id.uuidString)"
        )

        let opened = try MacScopeDocumentPackage.openPackage(from: packageURL)
        XCTAssertEqual(opened.snapshot.binaries.map(\.slot), [.primary, siblingSlot])
        XCTAssertEqual(opened.snapshot.binaries.map(\.selectedSliceIndex), [1, 7])
        XCTAssertEqual(opened.snapshot.analysis(in: .primary)?.functions.map(\.id), [fixture.primaryFunctionID])
        XCTAssertEqual(opened.snapshot.analysis(in: siblingSlot)?.functions.map(\.id), [fixture.siblingFunctionID])
        XCTAssertEqual(opened.snapshot.analysis(in: .primary)?.imageBytes, fixture.primaryBytes)
        XCTAssertEqual(opened.snapshot.analysis(in: siblingSlot)?.imageBytes, fixture.siblingBytes)
        XCTAssertEqual(opened.snapshot.analysis(in: .primary)?.hexBytes.count, WorkspaceSnapshot.hexViewByteWindow)
        XCTAssertEqual(opened.snapshot.analysis(in: siblingSlot)?.hexBytes.count, WorkspaceSnapshot.hexViewByteWindow)
        XCTAssertEqual(opened.snapshot.addressOverrides[.primary(collidingVA)]?.customName, "primary_name")
        XCTAssertEqual(
            opened.snapshot.addressOverrides[ImageAddress(slot: siblingSlot, address: collidingVA)]?.customName,
            "sibling_name"
        )
        XCTAssertEqual(opened.snapshot.manualXRefs.first?.imageSlot, siblingSlot)
        XCTAssertEqual(opened.snapshot.bookmarks.first?.imageSlot, siblingSlot)
        XCTAssertEqual(opened.snapshot.segmentOverrides.first?.imageSlot, siblingSlot)
        XCTAssertEqual(opened.session?.focusedImageSlot, siblingSlot)
        XCTAssertEqual(opened.session?.selectedAddress, collidingVA)
        XCTAssertEqual(opened.session?.selectedSidebarItemID, "binary:\(snapshot.binaries[1].id.uuidString)")
        XCTAssertEqual(opened.attachmentsByBinaryID[snapshot.binaries[0].id], fixture.primaryBytes)
        XCTAssertEqual(opened.attachmentsByBinaryID[snapshot.binaries[1].id], fixture.siblingBytes)

        // Importing back into the source DB forces UUID collision remapping. Every image bucket,
        // attachment, authoring slot, and selected-slice identity must survive that remap.
        let imported = try database.importPackage(from: packageURL)
        XCTAssertEqual(imported.snapshot.binaries.map(\.slot), [.primary, siblingSlot])
        XCTAssertNotEqual(imported.snapshot.binaries.map(\.id), snapshot.binaries.map(\.id))
        XCTAssertEqual(imported.snapshot.analysis(in: .primary)?.functions.first?.name, "primary_function")
        XCTAssertEqual(imported.snapshot.analysis(in: siblingSlot)?.functions.first?.name, "sibling_function")
        XCTAssertNotEqual(
            imported.snapshot.analysis(in: .primary)?.functions.first?.id,
            fixture.primaryFunctionID
        )
        XCTAssertNotEqual(
            imported.snapshot.analysis(in: siblingSlot)?.functions.first?.id,
            fixture.siblingFunctionID
        )
        XCTAssertEqual(imported.snapshot.analysis(in: .primary)?.imageBytes, fixture.primaryBytes)
        XCTAssertEqual(imported.snapshot.analysis(in: siblingSlot)?.imageBytes, fixture.siblingBytes)
        XCTAssertEqual(imported.snapshot.bookmarks.first?.imageSlot, siblingSlot)
        XCTAssertEqual(imported.session.focusedImageSlot, siblingSlot)
        XCTAssertEqual(imported.session.selectedAddress, collidingVA)
        XCTAssertEqual(
            imported.session.selectedSidebarItemID,
            "binary:\(imported.snapshot.binaries[1].id.uuidString)"
        )
        XCTAssertEqual(imported.snapshot.binaries.map(\.selectedSliceIndex), [1, 7])
    }

    /// WS-5 multi-image oracle over the Step-4 collision fixture: both images use the same virtual
    /// address, so the only correct outcome is an image-local request and splice for each slot.
    @MainActor
    func testTwoImageCollisionFixtureRehydratesEachSlotIndependently() async throws {
        let fixture = twoImageFixture()
        let siblingSlot = ImageSlot(rawValue: 7)
        let provider = CollisionFixtureRehydrationProvider(
            primaryBytes: fixture.primaryBytes,
            siblingBytes: fixture.siblingBytes,
            sectionAddress: collidingVA
        )
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let state = try database.saveWorkspaceState(
            workspaceName: "Collision rehydration",
            snapshot: fixture.snapshot,
            selectedSidebarItemID: nil,
            selectedAddress: collidingVA,
            selectedTool: .project,
            editorMode: .disassembly,
            isInspectorPresented: true,
            sidebarSearchText: ""
        )
        let store = try XCTUnwrap(WorkspaceStore.restored(
            workspaceID: try XCTUnwrap(state.workspace.id),
            from: database,
            engine: provider
        ))

        await store.rehydrateLoadedImagesSynchronouslyForTesting()

        let primary = try XCTUnwrap(store.snapshot.analysis(in: .primary))
        let sibling = try XCTUnwrap(store.snapshot.analysis(in: siblingSlot))
        XCTAssertEqual(primary.sections.map(\.name), ["primary_rehydrated"])
        XCTAssertEqual(sibling.sections.map(\.name), ["sibling_rehydrated"])
        XCTAssertEqual(primary.sections.first?.address, collidingVA)
        XCTAssertEqual(sibling.sections.first?.address, collidingVA)
        XCTAssertEqual(primary.functions.map(\.id), [fixture.primaryFunctionID])
        XCTAssertEqual(sibling.functions.map(\.id), [fixture.siblingFunctionID])
        XCTAssertEqual(primary.imageBytes, fixture.primaryBytes)
        XCTAssertEqual(sibling.imageBytes, fixture.siblingBytes)

        let callsByByteCount = Dictionary(uniqueKeysWithValues: provider.calls.map {
            ($0.imageBytes.count, $0.requestedSliceIndex)
        })
        XCTAssertEqual(callsByByteCount[fixture.primaryBytes.count], .some(nil))
        XCTAssertEqual(callsByByteCount[fixture.siblingBytes.count], .some(nil))
        XCTAssertEqual(provider.calls.count, 2)
        XCTAssertFalse(store.isDirty)
    }

    @MainActor
    func testStaleRehydrationFailureDoesNotInvalidateNewerAnalysis() async throws {
        let fixture = twoImageFixture()
        let binary = try XCTUnwrap(fixture.snapshot.binary(in: .primary))
        let original = try XCTUnwrap(fixture.snapshot.analysis(in: .primary))
        var newer = original
        newer.functions[0].name = "new_structural_function"
        newer.stringLiteralCoverage = .complete
        let started = expectation(description: "old rehydration started")
        let provider = ControlledRehydrationFailureProvider(
            result: WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: newer]),
            started: started)
        defer { provider.release() }
        let store = WorkspaceStore(workspaceName: "stale failure",
            snapshot: WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: original]),
            engine: provider, autosaveScheduler: nil)
        store.rehydrateLoadedImages()
        await fulfillment(of: [started], timeout: 5)
        XCTAssertTrue(store.reanalyzeHonoringOverrides(in: .primary))
        await store.awaitPendingReanalysis()
        let landed = try XCTUnwrap(store.snapshot.analysis(in: .primary))
        XCTAssertEqual(landed.functions.first?.name, "new_structural_function")
        XCTAssertFalse(provider.finished)
        provider.release()
        await store.awaitCurrentRehydrationForTesting()
        XCTAssertTrue(provider.releasedBeforeTimeout)
        let result = try XCTUnwrap(store.snapshot.analysis(in: .primary))
        XCTAssertEqual(result.functions, landed.functions)
        XCTAssertEqual(result.diagnostics, landed.diagnostics)
        XCTAssertEqual(result.stringLiteralCoverage, .complete)
    }

    @MainActor
    func testCurrentRehydrationFailureRemainsVisible() async throws {
        let fixture = twoImageFixture()
        let binary = try XCTUnwrap(fixture.snapshot.binary(in: .primary))
        let original = try XCTUnwrap(fixture.snapshot.analysis(in: .primary))
        let snapshot = WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: original])
        let started = expectation(description: "current rehydration started")
        let provider = ControlledRehydrationFailureProvider(result: snapshot, started: started)
        defer { provider.release() }
        let store = WorkspaceStore(workspaceName: "current failure", snapshot: snapshot,
            engine: provider, autosaveScheduler: nil)
        store.rehydrateLoadedImages()
        await fulfillment(of: [started], timeout: 5)
        provider.release()
        await store.awaitCurrentRehydrationForTesting()
        XCTAssertTrue(provider.releasedBeforeTimeout)
        let result = try XCTUnwrap(store.snapshot.analysis(in: .primary))
        XCTAssertEqual(result.functions, original.functions)
        XCTAssertTrue(result.diagnostics.contains { $0.message.hasPrefix("Couldn’t restore derived analysis:") })
    }

    @MainActor
    func testArchiveMemberSaveReopenReanalysisUsesExactOuterContainerSelection() throws {
        let outerArchiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PerImagePersistence-\(UUID().uuidString).a")
        try Data(repeating: 0xa5, count: 512).write(to: outerArchiveURL, options: [.atomic])
        defer { try? FileManager.default.removeItem(at: outerArchiveURL) }

        let payload = Data([0x7f, 0x45, 0x4c, 0x46, 0x55, 0x66])
        let selection = ELFArchiveMemberSelection(
            container: ELFArchiveContainerIdentity(
                byteCount: 512,
                sha256: MacScopeDocumentPackage.fileHash(for: Data(repeating: 0xa5, count: 512))
            ),
            member: ELFArchiveMemberIdentity(
                index: 1,
                archiveHeaderIndex: 3,
                name: "member.o",
                payloadOffset: 128,
                byteCount: payload.count,
                sha256: MacScopeDocumentPackage.fileHash(for: payload)
            )
        )
        let binary = BinaryImage(
            id: UUID(),
            name: "member.o",
            path: outerArchiveURL.path,
            kind: "ELF relocatable object",
            architecture: "arm64",
            elfArchiveMemberIdentity: selection
        )
        var analysis = ImageAnalysis()
        analysis.hexBytes = payload
        analysis.imageBytes = payload
        analysis.analysisInputFingerprint = try AnalysisInputFingerprint(
            imageSlot: .primary,
            binaryID: binary.id,
            binaryName: binary.name,
            binaryPath: binary.path,
            selectedSliceIndex: nil,
            artifactIdentity: nil,
            elfArchiveMemberIdentity: selection,
            imageByteCount: UInt64(payload.count),
            imageBytesSHA256: MacScopeDocumentPackage.fileHash(for: payload),
            facets: [],
            overallSHA256: String(repeating: "b", count: 64)
        )
        let snapshot = WorkspaceSnapshot(
            binaries: [binary],
            analysisBySlot: [.primary: analysis]
        )
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let workspace = try database.saveSnapshot(
            workspaceName: "Archive exact member",
            snapshot: snapshot
        )
        let reopened = try XCTUnwrap(
            database.loadSnapshot(workspaceID: try XCTUnwrap(workspace.id))
        )
        let provider = ArchiveSelectionRecordingProvider(returning: reopened)
        let store = WorkspaceStore(
            workspaceName: "Archive exact member",
            snapshot: reopened,
            engine: provider,
            autosaveScheduler: nil
        )

        store.withSynchronousReanalysis {
            store.setIsData(0, true)
        }

        XCTAssertEqual(provider.calls.count, 1)
        let call = try XCTUnwrap(provider.calls.first)
        XCTAssertEqual(call.url.standardizedFileURL, outerArchiveURL.standardizedFileURL)
        XCTAssertNil(call.selection.requestedMachOSliceIndex)
        XCTAssertEqual(call.selection.elfArchiveMember, selection)
        XCTAssertEqual(store.snapshot.binaries.first?.path, outerArchiveURL.path)
        XCTAssertEqual(store.snapshot.binaries.first?.elfArchiveMemberIdentity, selection)
        XCTAssertNil(store.lastReanalysisRefusal)

        // With the outer container gone, reanalysis must refuse with a typed result instead of
        // analyzing a temp copy of the retained member bytes, and keep the prior analysis.
        try FileManager.default.removeItem(at: outerArchiveURL)
        let priorAnalysis = store.snapshot.analysis(in: .primary)
        store.withSynchronousReanalysis {
            store.setIsData(0, false)
        }
        XCTAssertEqual(provider.calls.count, 1)
        XCTAssertEqual(
            store.lastReanalysisRefusal,
            .archiveContainerUnavailable(slot: .primary, path: outerArchiveURL.path)
        )
        XCTAssertEqual(store.snapshot.analysis(in: .primary)?.imageBytes, priorAnalysis?.imageBytes)
        XCTAssertEqual(store.snapshot.binaries.first?.path, outerArchiveURL.path)
        XCTAssertEqual(store.snapshot.binaries.first?.elfArchiveMemberIdentity, selection)
    }

    func testSingleNonPrimaryImageWritesVersion2() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let fixture = twoImageFixture()
        let sibling = fixture.snapshot.binaries[1]
        let siblingSlot = sibling.slot
        let snapshot = WorkspaceSnapshot(
            binaries: [sibling],
            analysisBySlot: [siblingSlot: fixture.snapshot.analysis(in: siblingSlot)!]
        )
        let state = try database.saveWorkspaceState(
            workspaceName: "Nonprimary",
            snapshot: snapshot,
            selectedSidebarItemID: nil,
            selectedAddress: nil,
            selectedTool: .project,
            editorMode: .disassembly,
            isInspectorPresented: true,
            sidebarSearchText: ""
        )
        let manifest = try XCTUnwrap(
            database.packageManifest(workspaceID: try XCTUnwrap(state.workspace.id))
        )
        XCTAssertEqual(manifest.formatVersion, 2)
        XCTAssertEqual(manifest.binaries.map(\.slot), [siblingSlot])
        XCTAssertEqual(manifest.imageAnalyses?.map(\.imageSlot), [siblingSlot])
    }

    func testVersion2ValidationRejectsDuplicateSlotsOrphanUnknownAndMissingAnalyses() throws {
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }
        var manifest = version2ManifestFixture()

        manifest.binaries[1].slot = .primary
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(error as? MacScopeDocumentPackage.PackageError, .duplicateImageSlot(.primary))
        }

        manifest = version2ManifestFixture()
        manifest.imageAnalyses?[1].imageSlot = .primary
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(error as? MacScopeDocumentPackage.PackageError, .duplicateImageAnalysisSlot(.primary))
        }

        manifest = version2ManifestFixture()
        let duplicateAnalysisBinaryID = manifest.binaries[0].id
        manifest.imageAnalyses?[1].binaryID = duplicateAnalysisBinaryID
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(
                error as? MacScopeDocumentPackage.PackageError,
                .duplicateImageAnalysisBinaryID(duplicateAnalysisBinaryID)
            )
        }

        manifest = version2ManifestFixture()
        let mismatchedBinaryID = manifest.binaries[1].id
        let mismatchedSlot = ImageSlot(rawValue: 9)
        manifest.imageAnalyses?[1].imageSlot = mismatchedSlot
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(
                error as? MacScopeDocumentPackage.PackageError,
                .imageAnalysisSlotMismatch(
                    binaryID: mismatchedBinaryID,
                    binarySlot: ImageSlot(rawValue: 7),
                    analysisSlot: mismatchedSlot
                )
            )
        }

        manifest = version2ManifestFixture()
        let unknownID = UUID(uuidString: "99999999-0000-0000-0000-000000000999")!
        manifest.imageAnalyses?[1].binaryID = unknownID
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(error as? MacScopeDocumentPackage.PackageError, .unknownImageAnalysisBinaryID(unknownID))
        }

        manifest = version2ManifestFixture()
        let missingBinaryID = manifest.binaries[1].id
        manifest.imageAnalyses?.removeLast()
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(error as? MacScopeDocumentPackage.PackageError, .missingImageAnalysis(missingBinaryID))
        }
    }

    func testVersion2ValidationRejectsPayloadInTheWrongOwnershipLayer() throws {
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }
        var manifest = version2ManifestFixture()
        manifest.analysis?.functions = [
            FunctionSummary(
                id: UUID(),
                name: "misplaced-derived",
                startAddress: collidingVA,
                endAddress: collidingVA + 4,
                confidence: 1
            )
        ]
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(
                error as? MacScopeDocumentPackage.PackageError,
                .version2TopLevelAnalysisContainsDerivedData
            )
        }

        manifest = version2ManifestFixture()
        let binaryID = manifest.binaries[0].id
        manifest.imageAnalyses?[0].analysis.addressOverrides = [
            AddressOverrideEntry(
                address: collidingVA,
                override: AddressOverride(customName: "misplaced-authoring")
            )
        ]
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(
                error as? MacScopeDocumentPackage.PackageError,
                .version2ImageAnalysisContainsAuthoring(binaryID)
            )
        }
    }

    func testVersion1ValidationRejectsVersion2ImageAnalysisRecords() throws {
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }
        var manifest = version2ManifestFixture()
        manifest.formatVersion = 1

        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(
                error as? MacScopeDocumentPackage.PackageError,
                .version1ContainsImageAnalyses
            )
        }
    }

    func testVersion2ValidationRejectsMissingAttachmentUnknownAttachmentAndMalformedVersion3() throws {
        let packageURL = temporaryPackageURL()
        defer { try? FileManager.default.removeItem(at: packageURL) }
        var manifest = version2ManifestFixture()
        let payloads = version2AttachmentPayloads()

        try MacScopeDocumentPackage.writeManifest(manifest, to: packageURL)
        let first = manifest.binaries[0]
        try payloads[first.id]?.write(
            to: MacScopeDocumentPackage.attachmentURL(in: packageURL, relativePath: first.attachmentRelativePath)
        )
        XCTAssertThrowsError(try MacScopeDocumentPackage.openPackage(from: packageURL)) { error in
            XCTAssertEqual(
                error as? MacScopeDocumentPackage.PackageError,
                .missingAttachment(manifest.binaries[1].attachmentRelativePath)
            )
        }

        let unknownID = UUID(uuidString: "99999999-0000-0000-0000-000000000999")!
        var extraPayloads = payloads
        extraPayloads[unknownID] = Data([0xff])
        XCTAssertThrowsError(
            try MacScopeDocumentPackage.writePackage(
                manifest,
                attachmentsByBinaryID: extraPayloads,
                to: temporaryPackageURL()
            )
        ) { error in
            XCTAssertEqual(error as? MacScopeDocumentPackage.PackageError, .unknownAttachmentBinaryID(unknownID))
        }

        manifest.formatVersion = 3
        XCTAssertThrowsError(try MacScopeDocumentPackage.validateManifest(manifest, in: packageURL)) { error in
            XCTAssertEqual(error as? ReconstructionPackageValidationError, .invalidDescriptor)
        }
    }

    private func twoImageFixture() -> (
        snapshot: WorkspaceSnapshot,
        primaryBytes: Data,
        siblingBytes: Data,
        primaryFunctionID: UUID,
        siblingFunctionID: UUID
    ) {
        let primarySlot = ImageSlot.primary
        let siblingSlot = ImageSlot(rawValue: 7)
        let primaryBinary = BinaryImage(
            id: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
            name: "primary",
            path: "/missing/primary",
            kind: "synthetic fixture",
            architecture: "arm64",
            selectedSliceIndex: 1,
            slot: primarySlot
        )
        let siblingBinary = BinaryImage(
            id: UUID(uuidString: "70000000-0000-0000-0000-000000000007")!,
            name: "sibling",
            path: "/missing/sibling",
            kind: "synthetic fixture",
            architecture: "arm64",
            selectedSliceIndex: 7,
            slot: siblingSlot
        )
        let primaryBytes = Data((0..<5_000).map { UInt8(truncatingIfNeeded: $0) })
        let siblingBytes = Data((0..<5_500).map { UInt8(truncatingIfNeeded: $0 &+ 0x55) })
        let primaryFunctionID = UUID(uuidString: "10000000-0000-0000-0000-000000000010")!
        let siblingFunctionID = UUID(uuidString: "70000000-0000-0000-0000-000000000070")!

        let primaryAnalysis = imageAnalysis(
            label: "primary",
            functionID: primaryFunctionID,
            bytes: primaryBytes
        )
        let siblingAnalysis = imageAnalysis(
            label: "sibling",
            functionID: siblingFunctionID,
            bytes: siblingBytes
        )
        let snapshot = WorkspaceSnapshot(
            binaries: [primaryBinary, siblingBinary],
            analysisBySlot: [primarySlot: primaryAnalysis, siblingSlot: siblingAnalysis]
        )
        return (snapshot, primaryBytes, siblingBytes, primaryFunctionID, siblingFunctionID)
    }

    private func imageAnalysis(label: String, functionID: UUID, bytes: Data) -> ImageAnalysis {
        let function = FunctionSummary(
            id: functionID,
            name: "\(label)_function",
            startAddress: collidingVA,
            endAddress: collidingVA + 4,
            confidence: 1.0
        )
        return ImageAnalysis(
            functions: [function],
            symbols: [
                SymbolSummary(
                    id: stableID(label: label, suffix: 1),
                    name: "_\(label)_symbol",
                    address: collidingVA,
                    kind: "export",
                    libraryName: nil
                )
            ],
            imports: [
                ImportSummary(
                    id: stableID(label: label, suffix: 2),
                    name: "_\(label)_import",
                    libraryName: "/usr/lib/libSystem.B.dylib",
                    libraryOrdinal: 1
                )
            ],
            indirectSymbols: [
                IndirectSymbolSummary(
                    id: stableID(label: label, suffix: 3),
                    kind: "lazySymbolPointer",
                    sourceSection: "__DATA,__la_symbol_ptr",
                    address: collidingVA + 0x100,
                    entrySize: 8,
                    tableIndex: 0,
                    rawSymbolIndex: 0,
                    symbolIndex: 0,
                    symbolName: "_\(label)_import",
                    libraryOrdinal: 1,
                    libraryName: "/usr/lib/libSystem.B.dylib",
                    isLocal: false,
                    isAbsolute: false
                )
            ],
            exports: [
                ExportSummary(
                    id: stableID(label: label, suffix: 4),
                    name: "_\(label)_export",
                    address: collidingVA,
                    source: "LC_DYLD_INFO"
                )
            ],
            stringLiterals: [
                StringLiteralSummary(
                    id: stableID(label: label, suffix: 5),
                    value: "\(label)-string",
                    address: collidingVA + 0x200,
                    sourceSection: "__TEXT,__cstring",
                    byteLength: label.utf8.count + 7
                )
            ],
            basicBlocks: [
                BasicBlockSummary(
                    id: stableID(label: label, suffix: 6),
                    functionID: functionID,
                    startAddress: collidingVA,
                    endAddress: collidingVA + 4,
                    instructionCount: 1
                )
            ],
            instructions: [
                InstructionRow(
                    address: collidingVA,
                    bytes: "c0 03 5f d6",
                    mnemonic: "\(label)_ret",
                    operands: "",
                    hasBreakpoint: label == "sibling",
                    comment: "\(label)-comment"
                )
            ],
            xrefs: [
                XRef(
                    id: stableID(label: label, suffix: 7),
                    from: collidingVA,
                    to: collidingVA + 4,
                    kind: "\(label)_call"
                )
            ],
            controlFlowEdges: [
                ControlFlowEdge(
                    id: stableID(label: label, suffix: 8),
                    from: collidingVA,
                    to: collidingVA + 4,
                    kind: "\(label)_fallthrough"
                )
            ],
            hexBytes: Data(bytes.prefix(WorkspaceSnapshot.hexViewByteWindow)),
            imageBytes: bytes
        )
    }

    private func stableID(label: String, suffix: UInt8) -> UUID {
        let prefix = label == "primary" ? "10000000" : "70000000"
        return UUID(uuidString: "\(prefix)-0000-0000-0000-0000000000\(String(format: "%02x", suffix))")!
    }

    private func temporarySQLiteURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("PerImagePersistence-\(UUID().uuidString)")
            .appendingPathExtension("sqlite")
    }

    private func temporaryPackageURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("PerImagePersistence-\(UUID().uuidString)")
            .appendingPathExtension(MacScopeDocumentPackage.fileExtension)
    }

    private func packageBinary(id: UUID, slot: ImageSlot, data: Data) -> WorkspacePackageBinary {
        WorkspacePackageBinary(
            id: id,
            displayName: "binary-\(slot.rawValue)",
            originalPath: "/tmp/binary-\(slot.rawValue).bin",
            attachmentRelativePath: MacScopeDocumentPackage.attachmentRelativePath(
                for: id,
                originalPath: "/tmp/binary-\(slot.rawValue).bin"
            ),
            kind: "Mach-O executable",
            architecture: "arm64",
            fileHash: MacScopeDocumentPackage.fileHash(for: data),
            fileSize: Int64(data.count),
            slot: slot
        )
    }

    private func analysisFingerprint(
        binaryID: UUID,
        slot: ImageSlot,
        overallSHA256: String
    ) throws -> AnalysisInputFingerprint {
        try AnalysisInputFingerprint(
            imageSlot: slot,
            binaryID: binaryID,
            binaryName: "binary-\(slot.rawValue)",
            binaryPath: "/tmp/binary-\(slot.rawValue).bin",
            selectedSliceIndex: nil,
            artifactIdentity: nil,
            imageByteCount: 4,
            imageBytesSHA256: String(repeating: "c", count: 64),
            facets: [
                AnalysisFacetFingerprint(
                    kind: .selectedSliceBytes,
                    itemCount: 1,
                    byteCount: 4,
                    sha256: String(repeating: "d", count: 64)
                )
            ],
            overallSHA256: overallSHA256
        )
    }

    private func version2AttachmentPayloads() -> [UUID: Data] {
        [
            UUID(uuidString: "20000000-0000-0000-0000-000000000002")!: Data([0x20, 0x21]),
            UUID(uuidString: "70000000-0000-0000-0000-000000000007")!: Data([0x70, 0x71, 0x72])
        ]
    }

    private func version2ManifestFixture() -> WorkspacePackageManifest {
        let payloads = version2AttachmentPayloads()
        let primaryID = UUID(uuidString: "20000000-0000-0000-0000-000000000002")!
        let siblingID = UUID(uuidString: "70000000-0000-0000-0000-000000000007")!
        let primaryFunctionID = UUID(uuidString: "20000000-0000-0000-0000-000000000020")!
        let siblingFunctionID = UUID(uuidString: "70000000-0000-0000-0000-000000000070")!
        let siblingSlot = ImageSlot(rawValue: 7)
        return WorkspacePackageManifest(
            formatVersion: 2,
            documentID: UUID(uuidString: "dddddddd-dddd-dddd-dddd-dddddddddddd")!,
            workspaceUUID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            workspaceName: "Version 2 fixture",
            createdAt: Date(timeIntervalSince1970: 1_800_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_800_000_001),
            binaries: [
                packageBinary(id: primaryID, slot: .primary, data: payloads[primaryID]!),
                packageBinary(id: siblingID, slot: siblingSlot, data: payloads[siblingID]!)
            ],
            analysis: WorkspacePackageAnalysis(),
            imageAnalyses: [
                WorkspacePackageImageAnalysis(
                    binaryID: primaryID,
                    imageSlot: .primary,
                    analysis: WorkspacePackageAnalysis(
                        functions: [
                            FunctionSummary(
                                id: primaryFunctionID,
                                name: "primary",
                                startAddress: collidingVA,
                                endAddress: collidingVA + 4,
                                confidence: 1
                            )
                        ]
                    )
                ),
                WorkspacePackageImageAnalysis(
                    binaryID: siblingID,
                    imageSlot: siblingSlot,
                    analysis: WorkspacePackageAnalysis(
                        functions: [
                            FunctionSummary(
                                id: siblingFunctionID,
                                name: "sibling",
                                startAddress: collidingVA,
                                endAddress: collidingVA + 4,
                                confidence: 1
                            )
                        ]
                    )
                )
            ],
            session: nil
        )
    }

    /// Captured from the real database-backed package writer at Phase-2 base SHA
    /// `e5157f60302308deaeb906c31bacadc4f0959fac`, using the deterministic fixture in
    /// `testSinglePrimaryManifestWritesExactLegacyVersion1Bytes`.
    private func prePhase3ProductionVersion1ManifestBytes() -> Data {
        Data(#"""
        {
          "analysis" : {
            "addressOverrides" : [
              {
                "address" : 4294967296,
                "override" : {
                  "customName" : "legacy_name"
                }
              }
            ],
            "basicBlocks" : [

            ],
            "bookmarks" : [

            ],
            "controlFlowEdges" : [

            ],
            "exports" : [

            ],
            "functions" : [
              {
                "confidence" : 1,
                "endAddress" : 4294967300,
                "id" : "33333333-3333-3333-3333-333333333333",
                "name" : "legacy_function",
                "startAddress" : 4294967296
              }
            ],
            "imports" : [

            ],
            "indirectSymbols" : [

            ],
            "instructions" : [

            ],
            "manualXRefs" : [

            ],
            "segmentOverrides" : [

            ],
            "stringLiterals" : [

            ],
            "symbols" : [

            ],
            "typeDefinitions" : [

            ],
            "xrefs" : [

            ]
          },
          "binaries" : [
            {
              "architecture" : "arm64",
              "attachmentRelativePath" : "attachments\/22222222-2222-2222-2222-222222222222\/legacy.bin",
              "displayName" : "legacy",
              "fileHash" : "65ab12a8ff3263fbc257e5ddf0aa563c64573d0bab1f1115b9b107834cfa6971",
              "fileSize" : 4,
              "id" : "22222222-2222-2222-2222-222222222222",
              "kind" : "synthetic fixture",
              "originalPath" : "\/tmp\/legacy.bin",
              "selectedSliceIndex" : 2
            }
          ],
          "bookmarkResolutionDecision" : "resolve_stored_bookmarks",
          "createdAt" : "2027-01-15T08:00:00.000Z",
          "documentID" : "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD",
          "formatIdentifier" : "com.jeff.macscope.workspace-package",
          "formatVersion" : 1,
          "inputCopyingDecision" : "copy_inputs_into_package",
          "modifiedAt" : "2027-01-15T08:00:00.000Z",
          "session" : {
            "editorMode" : "Graph",
            "isInspectorPresented" : false,
            "selectedAddress" : 4294967296,
            "selectedSidebarItemID" : "function:33333333-3333-3333-3333-333333333333",
            "selectedTool" : "Symbols",
            "sidebarSearchText" : "_legacy",
            "updatedAt" : "2027-01-15T08:00:00.000Z"
          },
          "workspaceName" : "Legacy Production V1",
          "workspaceUUID" : "11111111-1111-1111-1111-111111111111"
        }
        """#.utf8)
    }

    func test863PackageCoverageIsDerivedAndMissingMeansUnknown() throws {
        let states: [StringLiteralCoverage] = [
            .complete, .notAttempted, .incomplete(.stringCountLimitReached),
            .incomplete(.unterminatedField)
        ]
        for state in states {
            var image = ImageAnalysis()
            image.stringLiteralCoverage = state
            let analysis = WorkspacePackageAnalysis(imageAnalysis: image)
            XCTAssertTrue(analysis.hasDerivedPayload)
            let decoded = try JSONDecoder().decode(WorkspacePackageAnalysis.self,
                from: JSONEncoder().encode(analysis))
            XCTAssertEqual(decoded.stringLiteralCoverage, state)
            XCTAssertEqual(decoded.imageAnalysis(hexBytes: Data()).stringLiteralCoverage, state)
            let snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: image])
            XCTAssertEqual(WorkspacePackageAnalysis(snapshot: snapshot).stringLiteralCoverage, state)
            XCTAssertNil(WorkspacePackageAnalysis(authoringFrom: snapshot).stringLiteralCoverage)
        }
        let legacy = try JSONDecoder().decode(WorkspacePackageAnalysis.self, from: Data("{}".utf8))
        XCTAssertNil(legacy.stringLiteralCoverage)
        XCTAssertFalse(legacy.hasDerivedPayload)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: JSONEncoder().encode(legacy)) as? [String: Any])
        XCTAssertNil(object["stringLiteralCoverage"])
    }

    func test863CoverageSurvivesDocumentPromotionAndCollapse() throws {
        func binary(_ slot: ImageSlot) -> WorkspacePackageBinary {
            let id = UUID()
            return WorkspacePackageBinary(id: id, displayName: "coverage",
                originalPath: "/fixture", attachmentRelativePath: "attachments/\(id.uuidString)/fixture",
                kind: "synthetic fixture", architecture: "arm64", fileHash: "", fileSize: 0, slot: slot)
        }
        let primary = binary(.primary)
        let sibling = binary(ImageSlot(rawValue: 7))
        let coverage = StringLiteralCoverage.incomplete(.unterminatedField)
        let legacy = WorkspacePackageManifest(
            documentID: UUID(), workspaceUUID: UUID(), workspaceName: "coverage",
            createdAt: Date(timeIntervalSince1970: 0), modifiedAt: Date(timeIntervalSince1970: 0),
            binaries: [primary, sibling],
            analysis: WorkspacePackageAnalysis(stringLiteralCoverage: coverage), session: nil)
        let promoted = try MacScopeDocumentPackage.preparedManifest(legacy, reconstructionState: .empty)
        XCTAssertEqual(promoted.formatVersion, WorkspacePackageManifest.multiImageFormatVersion)
        XCTAssertNil(promoted.analysis?.stringLiteralCoverage)
        XCTAssertEqual(promoted.imageAnalyses?.first?.analysis.stringLiteralCoverage, coverage)
        XCTAssertNil(promoted.imageAnalyses?.last?.analysis.stringLiteralCoverage)

        var single = promoted
        single.binaries = [primary]
        single.imageAnalyses = promoted.imageAnalyses?.filter { $0.binaryID == primary.id }
        let collapsed = try MacScopeDocumentPackage.preparedManifest(single, reconstructionState: .empty)
        XCTAssertEqual(collapsed.formatVersion, WorkspacePackageManifest.currentFormatVersion)
        XCTAssertNil(collapsed.imageAnalyses)
        XCTAssertEqual(collapsed.analysis?.stringLiteralCoverage, coverage)
    }

    func test863DatabaseReloadPreservesImageLocalStringCoverage() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var snapshot = twoImageFixture().snapshot
        snapshot.analysisBySlot[.primary]?.stringLiteralCoverage = .complete
        snapshot.analysisBySlot[ImageSlot(rawValue: 7)]?.stringLiteralCoverage =
            .incomplete(.stringCountLimitReached)
        let workspace = try database.saveSnapshot(workspaceName: "coverage", snapshot: snapshot)
        let workspaceID = try XCTUnwrap(workspace.id)
        let restored = try XCTUnwrap(try database.loadSnapshot(workspaceID: workspaceID))
        for slot in [ImageSlot.primary, ImageSlot(rawValue: 7)] {
            XCTAssertEqual(restored.analysis(in: slot)?.stringLiteralCoverage,
                           snapshot.analysis(in: slot)?.stringLiteralCoverage)
            XCTAssertEqual(restored.analysis(in: slot)?.stringLiterals, snapshot.analysis(in: slot)?.stringLiterals)
        }
    }
}

private final class ControlledRehydrationFailureProvider: AnalysisProviding, @unchecked Sendable {
    private enum Failure: Error { case expected, timedOut }
    private let result: WorkspaceSnapshot
    private let started: XCTestExpectation
    private let gate = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var outcome: Bool?

    init(result: WorkspaceSnapshot, started: XCTestExpectation) {
        self.result = result
        self.started = started
    }

    func release() { gate.signal() }
    var finished: Bool { lock.lock(); defer { lock.unlock() }; return outcome != nil }
    var releasedBeforeTimeout: Bool { lock.lock(); defer { lock.unlock() }; return outcome == true }

    func analyze(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                 cancellation: AnalysisCancellationToken) throws -> WorkspaceSnapshot { result }
    func analyze(url: URL, selection: BinaryLoadSelection, overrides: [UInt64: AddressOverride],
                 cancellation: AnalysisCancellationToken) throws -> WorkspaceSnapshot { result }
    func openBinary(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                    cancellation: AnalysisCancellationToken) async throws -> WorkspaceSnapshot { result }
    func openBinary(url: URL, selection: BinaryLoadSelection, overrides: [UInt64: AddressOverride],
                    cancellation: AnalysisCancellationToken) async throws -> WorkspaceSnapshot { result }
    func rehydrate(imageBytes: Data, requestedSliceIndex: Int?, preserving persisted: ImageAnalysis,
                   cancellation: AnalysisCancellationToken) throws -> ImageAnalysis {
        started.fulfill()
        let released = gate.wait(timeout: .now() + 10) == .success
        lock.lock(); outcome = released; lock.unlock()
        throw released ? Failure.expected : Failure.timedOut
    }
}

private enum CollisionFixtureRehydrationError: Error {
    case unexpectedAnalysis
    case unknownBytes
}

private final class CollisionFixtureRehydrationProvider: AnalysisProviding, @unchecked Sendable {
    struct Call: Sendable {
        let imageBytes: Data
        let requestedSliceIndex: Int?
    }

    private let primaryBytes: Data
    private let siblingBytes: Data
    private let sectionAddress: UInt64
    private let lock = NSLock()
    private var recordedCalls: [Call] = []

    init(primaryBytes: Data, siblingBytes: Data, sectionAddress: UInt64) {
        self.primaryBytes = primaryBytes
        self.siblingBytes = siblingBytes
        self.sectionAddress = sectionAddress
    }

    var calls: [Call] {
        lock.lock()
        defer { lock.unlock() }
        return recordedCalls
    }

    func analyze(
        url: URL,
        requestedSliceIndex: Int?,
        overrides: [UInt64: AddressOverride],
        cancellation: AnalysisCancellationToken
    ) throws -> WorkspaceSnapshot {
        throw CollisionFixtureRehydrationError.unexpectedAnalysis
    }

    func openBinary(
        url: URL,
        requestedSliceIndex: Int?,
        overrides: [UInt64: AddressOverride],
        cancellation: AnalysisCancellationToken
    ) async throws -> WorkspaceSnapshot {
        throw CollisionFixtureRehydrationError.unexpectedAnalysis
    }

    func rehydrate(
        imageBytes: Data,
        requestedSliceIndex: Int?,
        preserving persisted: ImageAnalysis,
        cancellation: AnalysisCancellationToken
    ) throws -> ImageAnalysis {
        lock.lock()
        recordedCalls.append(Call(
            imageBytes: imageBytes,
            requestedSliceIndex: requestedSliceIndex
        ))
        lock.unlock()

        let name: String
        if imageBytes == primaryBytes {
            name = "primary_rehydrated"
        } else if imageBytes == siblingBytes {
            name = "sibling_rehydrated"
        } else {
            throw CollisionFixtureRehydrationError.unknownBytes
        }
        var result = persisted
        result.sections = [SectionSummary(
            id: UUID(), name: name, address: sectionAddress, size: 4,
            fileOffset: 0, isExecutable: true
        )]
        return result
    }
}

private enum ArchiveSelectionRecordingProviderError: Error {
    case unexpectedLegacyEntryPoint
}

private final class ArchiveSelectionRecordingProvider: AnalysisProviding, @unchecked Sendable {
    struct Call: Sendable {
        let url: URL
        let selection: BinaryLoadSelection
    }

    private let returnedSnapshot: WorkspaceSnapshot
    private let lock = NSLock()
    private var recordedCalls: [Call] = []

    init(returning snapshot: WorkspaceSnapshot) {
        returnedSnapshot = snapshot
    }

    var calls: [Call] {
        lock.lock()
        defer { lock.unlock() }
        return recordedCalls
    }

    func analyze(
        url: URL,
        requestedSliceIndex: Int?,
        overrides: [UInt64: AddressOverride],
        cancellation: AnalysisCancellationToken
    ) throws -> WorkspaceSnapshot {
        throw ArchiveSelectionRecordingProviderError.unexpectedLegacyEntryPoint
    }

    func analyze(
        url: URL,
        selection: BinaryLoadSelection,
        overrides: [UInt64: AddressOverride],
        cancellation: AnalysisCancellationToken
    ) throws -> WorkspaceSnapshot {
        lock.lock()
        recordedCalls.append(Call(url: url, selection: selection))
        lock.unlock()
        return returnedSnapshot
    }

    func openBinary(
        url: URL,
        requestedSliceIndex: Int?,
        overrides: [UInt64: AddressOverride],
        cancellation: AnalysisCancellationToken
    ) async throws -> WorkspaceSnapshot {
        throw ArchiveSelectionRecordingProviderError.unexpectedLegacyEntryPoint
    }
}
