import Foundation
import XCTest
@testable import MacScope

// Native protected-member inventory (paths relative to MacScope):
// Member | Owner file:line | Included/excluded | Reason
// Target and all-slot overrides | Models/AnalysisModels+WorkspaceSnapshot.swift:192 | included | exact requested delta only
// Signature, applied type | Models/AnalysisModels+Overrides.swift:1018,1029 | included | native override members
// Session signature authority | Models/AnalysisModels+Overrides.swift:1026 | included | explicit sidecar; Codable omits it
// Shape, procedure/data/undefined flags | Models/AnalysisModels+Overrides.swift:1016,1038,1042,1047 | included | native override members
// Tags, colors | Models/AnalysisModels+Overrides.swift:1010,1012 | included | native override members
// Patches | Models/AnalysisModels+Overrides.swift:1053 | included | all-slot override member
// Type catalog | Models/AnalysisModels+WorkspaceSnapshot.swift:197 | included | independent global owner
// Imported prototypes | Models/AnalysisModels+WorkspaceSnapshot.swift:194 | included | canonical qualified entries
// Binary ID/slot/architecture/selection | Models/AnalysisModels.swift:196-225 | included | entire binary inventory
// Slice digest | Models/MachOSliceArtifactIdentity.swift:50 | included | existing artifact identity, no byte rehash
// Fingerprint/digests | Models/AnalysisFingerprint.swift:93 | included | every slot, including explicit absence
// Analysis generation | Models/AnalysisModels+WorkspaceSnapshot.swift:27 | included | precommit fence, annotation assignment advances it
// Document/installation/mutation | Stores/WorkspaceStore.swift:2090,2144,2610 | included | owner identity and revision fence
// Structural landing/Navigator generation | Stores/WorkspaceStore.swift:1790,2301 | included | all-slot fence and generation equality
// Other authoring | Models/AnalysisModels+WorkspaceSnapshot.swift:223-245 | included | xrefs/bookmarks/segments/catalogs/source links
// Navigator mirror | Stores/WorkspaceStore+NavigatorState.swift:663 | explicit effect | pure native operation, exact staged state and observed text
// Dirty/Undo/journal | Stores/WorkspaceStore.swift:9649-9669 | explicit effects | no staging writes; live dirty, undo restoration, one target record
// Source bytes and analysis products | Models/AnalysisModels+WorkspaceSnapshot.swift:44 | generation protected | immutable copy; existing fingerprints reused
// Container admission witness | Models/AnalysisModels.swift:220 | equality protected | BinaryImage equality covers non-Codable witness
// Findings | Stores/WorkspaceStore+AnalystFindingRevisions.swift:143 | protected | reject staged reconciliation with new stale marks
// UI selection/caches, package/disk history | Stores/WorkspaceStore.swift | excluded | outside annotation staging; VA3 publication responsibility

@MainActor
final class VerifiedCandidateIsolationTests: XCTestCase {
    private let key = ImageAddress.primary(0x1000)

    private func journal(_ store: WorkspaceStore) throws -> URL {
        let url = TestWorkRoot.authorityURL("va2-journal-\(UUID().uuidString)")
        store.editJournal = try EditJournalWriter(url: url,
            header: EditJournalHeader(base: WorkspacePackageAnalysis.entries(from: store.snapshot.addressOverrides),
                images: store.snapshot.binaries.sorted { $0.slot < $1.slot }.map {
                    // These synthetic images have no source bytes. Reuse the known empty
                    // SHA-256; never read or hash a real binary to create this fixture.
                    EditJournalImageIdentity(slot: $0.slot.rawValue, name: $0.name, kind: $0.kind,
                        architecture: $0.architecture, selectedSliceIndex: nil, uuid: nil, elfGNUBuildID: nil,
                        imageByteCount: 0, imageSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                }),
            sequence: 0, createHeader: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func write(_ store: WorkspaceStore, _ field: VerifiedAnnotationField = .name, _ value: String = "after") -> ScriptValue {
        store.writeAnnotationWithReadback(at: key.address, in: key.slot, field: field, text: value)
    }

    /// Full native semantic bytes/digest plus actual owner counts and journal bytes; this
    /// distinguishes precommit refusal from a compensating live edit with the same text.
    private func refused(_ store: WorkspaceStore, field: VerifiedAnnotationField = .name, value: String = "after",
                         code: String? = nil, file: StaticString = #filePath, line: UInt = #line) throws {
        let url = try journal(store)
        let measurement = try NativeCandidateMeasurement(snapshot: store.snapshot, overrides: store.snapshot.addressOverrides)
        let bytes = try VACanonicalJSON.encode(measurement.members)
        let journalBytes = try Data(contentsOf: url)
        let dirty = store.hasUnsavedChanges
        let generation = store.mutationGeneration
        let mirror = store.navigatorState(for: key.slot)?.state()
        #if DEBUG
        let undoCount = store.verifiedAnnotationUndoCount
        var liveRead = false
        store.verifiedAnnotationReadbackTestHook = { _ in liveRead = true }
        #endif
        let reply = write(store, field, value)
        XCTAssertEqual(reply["ok"], .bool(false), file: file, line: line)
        XCTAssertEqual(reply["verification"]?["stage"], .string("candidate"), file: file, line: line)
        if let code { XCTAssertEqual(reply["verification"]?["code"], .string(code), file: file, line: line) }
        let after = try NativeCandidateMeasurement(snapshot: store.snapshot, overrides: store.snapshot.addressOverrides)
        XCTAssertEqual(try after.digest, try measurement.digest, file: file, line: line)
        XCTAssertEqual(try VACanonicalJSON.encode(after.members), bytes, file: file, line: line)
        XCTAssertEqual(try Data(contentsOf: url), journalBytes, file: file, line: line)
        XCTAssertEqual(store.editJournal?.appendedSequence, 0, file: file, line: line)
        XCTAssertEqual(store.mutationGeneration, generation, file: file, line: line)
        XCTAssertEqual(store.hasUnsavedChanges, dirty, file: file, line: line)
        XCTAssertEqual(store.navigatorState(for: key.slot)?.state(), mirror, file: file, line: line)
        #if DEBUG
        XCTAssertEqual(store.verifiedAnnotationUndoCount, undoCount, file: file, line: line)
        XCTAssertFalse(liveRead, "Refusal must occur before setter/readback", file: file, line: line)
        #endif
        XCTAssertFalse(store.undoManager.canUndo, file: file, line: line)
    }

    func testSetterSuccessWithOldIndependentReadbackIsRejected() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        let before = store.snapshot.addressOverrides
        // Simulates a successful stage write whose serializer independently reads old bytes.
        store.verifiedAnnotationCandidateBytesTestHook = { bytes in
            bytes = try VACanonicalJSON.encode(WorkspacePackageAnalysis.entries(from: before.filter { $0.key.slot == .primary }))
        }
        try refused(store, code: "missingCandidateField")
        #endif
    }

    func testSilentlyNormalizedCommentIsRejected() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        store.verifiedAnnotationCandidateBytesTestHook = { bytes in
            var entries = try JSONDecoder().decode([AddressOverrideEntry].self, from: bytes)
            entries[0].override.customComment = "silently changed"
            bytes = try VACanonicalJSON.encode(entries)
        }
        try refused(store, field: .comment, code: "missingCandidateField")
        #endif
    }

    func testCollateralTypePatchAndOtherFunctionAreRejected() throws {
        #if DEBUG
        let mutations: [(inout NativeAnnotationCandidate) -> Void] = [
            { $0.overrides[.primary(0x1000)]?.appliedTypeName = "collateral" },
            { $0.overrides[.primary(0x1000)]?.patch = BytePatch(bytes: [0x90]) },
            { $0.overrides[.primary(0x1010)]?.customComment = "collateral" },
            { $0.overrides[.primary(0x1010)]?.markAsProcedure = true },
            { $0.overrides[.primary(0x1010)]?.ownReturnAuthorityFile = "collateral" },
            { $0.overrides[.primary(0x1000)]?.customComment = "collateral" },
            { $0.snapshot.typeDefinitions.append(TypeDefinition(kind: .struct, name: "collateral")) },
            { $0.snapshot.importedPrototypes[.primary(0x1010)] = FunctionSignatureOverride(returnType: "int") },
            { $0.snapshot.binaries[0].architecture = "arm64e" }
        ]
        for mutation in mutations {
            let store = VerifiedAnnotationTestFixture.store()
            store.verifiedAnnotationCandidateTestHook = mutation
            try refused(store)
        }
        #endif
    }

    func testMissingMirrorIsRejected() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        store.verifiedAnnotationCandidateTestHook = {
            $0.mirror = NavigatorContractStore(toolchain: NavigatorStateBridge.pendingToolchain)
        }
        try refused(store, code: "expectedEffectMismatch")
        #endif
    }

    func testUnchangedNameWithMissingMirrorIsRejected() throws {
        try refused(VerifiedAnnotationTestFixture.store(), value: "before", code: "expectedEffectMismatch")
    }

    func testMissingProtectedProjectionMemberIsRejected() throws {
        #if DEBUG
        for member in NativeCandidateMeasurement.requiredMembers.sorted() {
            let store = VerifiedAnnotationTestFixture.store()
            store.verifiedAnnotationCandidateTestHook = { $0.measuredMembers.remove(member) }
            try refused(store, code: "measurementFailed")
        }
        #endif
    }

    func testSerializerDropsClearedOverrideWithProtectedTag() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        store.verifiedAnnotationCandidateBytesTestHook = { bytes in
            var entries = try JSONDecoder().decode([AddressOverrideEntry].self, from: bytes)
            entries.removeAll { $0.address == 0x1000 }
            bytes = try VACanonicalJSON.encode(entries)
        }
        try refused(store, value: "")
        #endif
    }

    func testSameAddressOtherSlotAndItsAnalysisCannotChange() throws {
        #if DEBUG
        for changeAnalysis in [false, true] {
            let store = VerifiedAnnotationTestFixture.store()
            store.verifiedAnnotationCandidateTestHook = { candidate in
                if changeAnalysis {
                    candidate.snapshot.analysisBySlot[VerifiedAnnotationTestFixture.sibling]?.functions.removeAll()
                } else {
                    candidate.overrides[ImageAddress(slot: VerifiedAnnotationTestFixture.sibling, address: 0x1000)]?.tag = "collateral"
                }
            }
            try refused(store, code: changeAnalysis ? "changedIdentity" : "protectedFieldMismatch")
        }
        #endif
    }

    func testCancellationDuringStageLeavesNoLiveEffects() async throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        store.verifiedAnnotationCandidateTestHook = { _ in
            withUnsafeCurrentTask { $0?.cancel() }
        }
        // Cancel a dedicated child task, not XCTest's task or a later test.
        try await Task { @MainActor in try self.refused(store, code: "cancelled") }.value
        #endif
    }

    func testChangedRevisionInstallationAndExtraAnnotationAreTyped() throws {
        #if DEBUG
        for mode in 0..<3 {
            let store = VerifiedAnnotationTestFixture.store()
            store.verifiedAnnotationCandidateTestHook = { candidate in
                switch mode {
                case 0: candidate.revision += 1
                case 1: candidate.installationID = UUID()
                default: candidate.overrides[.primary(0x5000)] = AddressOverride(customName: "extra")
                }
            }
            try refused(store, code: mode == 2 ? "unexpectedAnnotation" : "changedIdentity")
        }
        #endif
    }

    func testMalformedMeasurementRefusesBeforeCommit() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        store.verifiedAnnotationCandidateBytesTestHook = { $0 = Data("not JSON".utf8) }
        try refused(store, code: "measurementFailed")
        #endif
    }

    func testExpectedEffectsMirrorDirtyOneJournalRecordAndUndoRestoration() throws {
        for field in VerifiedAnnotationField.allCases {
            let store = VerifiedAnnotationTestFixture.store()
            let before = store.snapshot.addressOverrides
            let dirty = store.hasUnsavedChanges
            let url = try journal(store)
            let reply = write(store, field)
            XCTAssertEqual(reply["verification"], .string("candidateReadbackVerified"))
            XCTAssertTrue(store.hasUnsavedChanges)
            let records = try EditJournalReader.read(Data(contentsOf: url)).records
            XCTAssertEqual(records.count, 1)
            guard case .override(_, let slot, let address, let value) = try XCTUnwrap(records.first) else {
                return XCTFail("Expected one target override journal record")
            }
            XCTAssertEqual(slot, key.slot.rawValue)
            XCTAssertEqual(address, key.address)
            XCTAssertEqual(value, store.snapshot.addressOverrides[key])
            if field == .name {
                XCTAssertTrue(WorkspaceStore.verifiedNameMirror(try XCTUnwrap(store.navigatorState(for: key.slot)),
                    snapshot: store.snapshot, key: key, observed: "after"))
            }
            #if DEBUG
            XCTAssertEqual(store.verifiedAnnotationUndoCount, field == .name ? 2 : 1)
            #endif
            store.undoManager.undo()
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            XCTAssertEqual(store.hasUnsavedChanges, dirty)
            #if DEBUG
            XCTAssertEqual(store.verifiedAnnotationUndoCount, 0)
            #endif
            XCTAssertFalse(store.undoManager.canUndo)
        }
    }

    func testSoleNameClearAndSessionAuthoritySurviveNativeRoundTrip() throws {
        for soleName in [true, false] {
            let store = VerifiedAnnotationTestFixture.store()
            var value = soleName ? AddressOverride(customName: "before") : store.snapshot.addressOverrides[key]!
            if !soleName { value.ownReturnAuthorityFile = "session-authority" }
            store.applyOverride(key, value, actionName: "fixture")
            let reply = write(store, .name, soleName ? "" : "after")
            XCTAssertEqual(reply["verification"], .string("candidateReadbackVerified"))
            if soleName { XCTAssertNil(store.snapshot.addressOverrides[key]) }
            else { XCTAssertEqual(store.snapshot.addressOverrides[key]?.ownReturnAuthorityFile, "session-authority") }
        }
    }

    // MARK: VA-SCOPE S3: staged type candidate

    private let shaped = ImageAddress.primary(VerifiedAnnotationTestFixture.dataEntry)
    private let plain = ImageAddress.primary(VerifiedAnnotationTestFixture.plainData)

    /// The typed refusal code of a staging call, or nil when it staged.
    private func stageFailure(_ store: WorkspaceStore, _ address: ImageAddress, _ requested: String?) -> String? {
        do { _ = try store.stageVerifiedType(at: address, requested: requested); return nil }
        catch let error as VerifiedCandidateError { return error.code.rawValue }
        catch VAVerificationError.candidateMismatch { return "candidateMismatch" }
        catch { return "\(error)" }
    }

    private struct LiveCut: Equatable {
        let overrides: [ImageAddress: AddressOverride]
        let types: [TypeDefinition]
        let canUndo: Bool
        let undoCount: Int
        let generation: WorkspaceDocumentMutationGeneration
        let dirty: Bool
        let mirror: NavigatorEngineState?
    }

    private func cut(_ store: WorkspaceStore) -> LiveCut {
        #if DEBUG
        let undoCount = store.verifiedAnnotationUndoCount
        #else
        let undoCount = 0
        #endif
        return LiveCut(overrides: store.snapshot.addressOverrides, types: store.snapshot.typeDefinitions,
                       canUndo: store.undoManager.canUndo, undoCount: undoCount,
                       generation: store.mutationGeneration, dirty: store.hasUnsavedChanges,
                       mirror: store.navigatorState(for: .primary)?.state())
    }

    func testTypeStagingLeavesTheLiveWorkspaceUntouched() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let url = try journal(store)
        let journalBytes = try Data(contentsOf: url)
        let before = cut(store)
        let candidate = try store.stageVerifiedType(at: shaped, requested: "Header")
        XCTAssertEqual(cut(store), before, "overrides, type table, undo history, generation, dirty flag and mirror")
        XCTAssertEqual(try Data(contentsOf: url), journalBytes)
        XCTAssertEqual(store.editJournal?.appendedSequence, 0)
        // The candidate carries the type and preserves what the trace says a type does not touch.
        let staged = try XCTUnwrap(candidate.overrides[shaped])
        XCTAssertEqual(staged.appliedTypeName, "Header")
        XCTAssertEqual(staged.tag, "data-tag")
        XCTAssertEqual(staged.dataShape, store.snapshot.addressOverrides[shaped]?.dataShape)
        XCTAssertFalse(staged.isData)
        XCTAssertNil(store.snapshot.addressOverrides[shaped]?.appliedTypeName)
        XCTAssertTrue(WorkspaceStore.verifiedTypeMirror(candidate.mirror, snapshot: candidate.snapshot, key: shaped, observed: "Header"))
        let liveMirror = store.navigatorState(for: shaped.slot)
            ?? NavigatorContractStore(toolchain: NavigatorStateBridge.pendingToolchain)
        XCTAssertFalse(WorkspaceStore.verifiedTypeMirror(liveMirror, snapshot: store.snapshot, key: shaped,
            observed: "Header"), "the live mirror never saw the type")
        // Staging a type must not disturb name staging on the same store.
        XCTAssertNil(stageFailure(store, shaped, "Other"))
        XCTAssertEqual(cut(store), before)
    }

    func testTypeClearStagesAgainstALiveTypeWithoutTouchingIt() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        store.setAppliedType(shaped.address, in: shaped.slot, name: "Header")
        XCTAssertEqual(store.snapshot.addressOverrides[shaped]?.appliedTypeName, "Header")
        let before = cut(store)
        let candidate = try store.stageVerifiedType(at: shaped, requested: nil)
        XCTAssertEqual(cut(store), before)
        let staged = try XCTUnwrap(candidate.overrides[shaped])
        XCTAssertNil(staged.appliedTypeName)
        XCTAssertEqual(staged.tag, "data-tag")
        XCTAssertEqual(staged.dataShape, store.snapshot.addressOverrides[shaped]?.dataShape)
        XCTAssertTrue(WorkspaceStore.verifiedTypeMirror(candidate.mirror, snapshot: candidate.snapshot, key: shaped, observed: nil))
        XCTAssertEqual(store.snapshot.addressOverrides[shaped]?.appliedTypeName, "Header")
    }

    func testTypeStagingRefusalsAreTypedAndLeaveTheWorkspaceUntouched() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let before = cut(store)
        XCTAssertEqual(stageFailure(store, shaped, "Nope"), "unresolvedType")
        XCTAssertEqual(stageFailure(store, shaped, "Dup"), "ambiguousType")
        XCTAssertEqual(stageFailure(store, .primary(0x1000), "Header"), "functionEntryTarget")
        XCTAssertEqual(stageFailure(store, .primary(VerifiedAnnotationTestFixture.outside), "Header"), "addressOutsideSegments")
        for invalid in ["", "   ", " Header ", "a\nb", "a\0b", String(repeating: "t", count: 257)] {
            XCTAssertEqual(stageFailure(store, shaped, invalid), "invalidTypeName", "\(invalid.debugDescription)")
        }
        XCTAssertEqual(cut(store), before)
        // A slot with no segment layout cannot prove containment, so it fails closed.
        let bare = VerifiedAnnotationTestFixture.typedStore(withLayout: false)
        XCTAssertEqual(stageFailure(bare, shaped, "Header"), "addressOutsideSegments")
        // Clearing is not subject to type resolution, but it is subject to the target rules.
        XCTAssertEqual(stageFailure(store, .primary(0x1000), nil), "functionEntryTarget")
        XCTAssertEqual(stageFailure(store, .primary(VerifiedAnnotationTestFixture.outside), nil), "addressOutsideSegments")
    }

    func testTypeCandidateAlsoChangingAProtectedMemberIsRefused() throws {
        #if DEBUG
        let protectedMutations: [(String, (inout NativeAnnotationCandidate) -> Void)] = [
            ("tag", { $0.overrides[.primary(0x2010)]?.tag = "collateral" }),
            ("dataShape", { $0.overrides[.primary(0x2010)]?.dataShape = DataShapeOverride(kind: .alignment, alignment: 8) }),
            ("dataShape cleared", { $0.overrides[.primary(0x2010)]?.dataShape = nil }),
            ("isData", { $0.overrides[.primary(0x2010)]?.isData = true }),
            ("isUndefined", { $0.overrides[.primary(0x2010)]?.isUndefined = true }),
            ("markAsProcedure", { $0.overrides[.primary(0x2010)]?.markAsProcedure = true }),
            ("another address tag", { $0.overrides[.primary(0x1010)]?.tag = "collateral" }),
            ("another address procedure", { $0.overrides[.primary(0x1010)]?.markAsProcedure = true }),
        ]
        for (name, mutation) in protectedMutations {
            let store = VerifiedAnnotationTestFixture.typedStore()
            let before = cut(store)
            store.verifiedAnnotationCandidateTestHook = mutation
            XCTAssertEqual(stageFailure(store, shaped, "Header"), "protectedFieldMismatch", name)
            XCTAssertEqual(cut(store), before, name)
        }
        // The type catalog is an independent global owner: editing it on the candidate moves the snapshot
        // generation, so the identity guard refuses it before the protected-member comparison.
        let catalogStore = VerifiedAnnotationTestFixture.typedStore()
        let catalogBefore = cut(catalogStore)
        catalogStore.verifiedAnnotationCandidateTestHook = {
            $0.snapshot.typeDefinitions.append(TypeDefinition(kind: .struct, name: "collateral"))
        }
        XCTAssertEqual(stageFailure(catalogStore, shaped, "Header"), "changedIdentity", "type catalog")
        XCTAssertEqual(cut(catalogStore), catalogBefore)
        // Annotation members the supported-annotation comparison itself sees.
        let comparedMutations: [(String, (inout NativeAnnotationCandidate) -> Void)] = [
            ("name beside the type", { $0.overrides[.primary(0x2010)]?.customName = "collateral" }),
            ("comment beside the type", { $0.overrides[.primary(0x2010)]?.customComment = "collateral" }),
            ("type at another address", { $0.overrides[.primary(0x1010)]?.appliedTypeName = "Other" }),
            ("name at another address", { $0.overrides[.primary(0x1010)]?.customName = "collateral" }),
        ]
        for (name, mutation) in comparedMutations {
            let store = VerifiedAnnotationTestFixture.typedStore()
            store.verifiedAnnotationCandidateTestHook = mutation
            XCTAssertEqual(stageFailure(store, shaped, "Header"), "candidateMismatch", name)
        }
        // A brand-new override elsewhere is an unexpected annotation.
        let store = VerifiedAnnotationTestFixture.typedStore()
        store.verifiedAnnotationCandidateTestHook = { $0.overrides[.primary(0x2020)] = AddressOverride(appliedTypeName: "Header") }
        XCTAssertEqual(stageFailure(store, shaped, "Header"), "unexpectedAnnotation")
        #endif
    }

    func testTypeOnlyCandidatesPassOnShapedAndPlainDataAddresses() throws {
        for address in [shaped, plain, ImageAddress.primary(VerifiedAnnotationTestFixture.namedData)] {
            let store = VerifiedAnnotationTestFixture.typedStore()
            let baseline = store.snapshot.addressOverrides[address]
            let candidate = try store.stageVerifiedType(at: address, requested: "Header")
            var expected = baseline ?? AddressOverride()
            expected.appliedTypeName = "Header"
            XCTAssertEqual(candidate.overrides[address], expected)
            XCTAssertEqual(candidate.overrides[address]?.dataShape, baseline?.dataShape, "an applied type must not change the shape")
            XCTAssertEqual(candidate.overrides[address]?.customName, baseline?.customName)
        }
    }

    // MARK: VA-SCOPE S6a: staged signature candidate

    private let entry = ImageAddress.primary(VerifiedAnnotationTestFixture.entry)

    private func signature(_ rows: [(String, String, String)], returnType: String? = "int") -> FunctionSignatureOverride {
        FunctionSignatureOverride(returnType: returnType, args: rows.map { ArgOverride(rowToken: $0.0, name: $0.1, type: $0.2) })
    }

    /// Installs a live signature (and optionally session authority) the way the store's own setters leave it.
    private func install(_ store: WorkspaceStore, at address: ImageAddress, _ value: FunctionSignatureOverride?,
                         authority: String? = nil) {
        var override = store.snapshot.addressOverrides[address] ?? AddressOverride()
        override.signature = value
        override.ownReturnAuthorityFile = authority
        store.applyOverride(address, override, actionName: "fixture")
    }

    private func signatureFailure(_ store: WorkspaceStore, _ address: ImageAddress, _ requested: FunctionSignatureOverride?) -> String? {
        do { _ = try store.stageVerifiedSignature(at: address, requested: requested); return nil }
        catch let error as VerifiedCandidateError { return error.code.rawValue }
        catch VAVerificationError.candidateMismatch { return "candidateMismatch" }
        catch { return "\(error)" }
    }

    func testSignatureStagingLeavesTheLiveWorkspaceUntouched() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        install(store, at: entry, signature([("a", "x", "int")]), authority: "session-authority")
        let url = try journal(store)
        let journalBytes = try Data(contentsOf: url)
        let before = cut(store)
        let requested = signature([("n1", "buf", "char *"), ("n2", "len", "size_t")], returnType: "ssize_t")
        let candidate = try store.stageVerifiedSignature(at: entry, requested: requested)
        XCTAssertEqual(cut(store), before, "overrides, undo history, generation, dirty flag and mirror")
        XCTAssertEqual(try Data(contentsOf: url), journalBytes)
        XCTAssertEqual(store.editJournal?.appendedSequence, 0)
        let staged = try XCTUnwrap(candidate.overrides[entry])
        XCTAssertEqual(staged.signature, requested)
        XCTAssertNil(staged.ownReturnAuthorityFile, "the signature didSet resets the session authority on the candidate")
        XCTAssertEqual(staged.customName, "before")
        XCTAssertEqual(staged.tag, "target")
        XCTAssertEqual(store.snapshot.addressOverrides[entry]?.ownReturnAuthorityFile, "session-authority")
        XCTAssertEqual(store.snapshot.addressOverrides[entry]?.signature, signature([("a", "x", "int")]))
        XCTAssertNil(stageFailure(store, shaped, "Other"), "staging a signature must not disturb type staging")
        XCTAssertEqual(cut(store), before)
    }

    func testSignatureClearStagesAgainstALiveSignatureWithoutTouchingIt() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        install(store, at: entry, signature([("a", "x", "int")]), authority: "session-authority")
        let before = cut(store)
        let candidate = try store.stageVerifiedSignature(at: entry, requested: nil)
        XCTAssertEqual(cut(store), before)
        let staged = try XCTUnwrap(candidate.overrides[entry])
        XCTAssertNil(staged.signature)
        XCTAssertNil(staged.ownReturnAuthorityFile)
        XCTAssertEqual(staged.customName, "before")
        XCTAssertNotNil(store.snapshot.addressOverrides[entry]?.signature)
    }

    func testSignatureStagingRefusalsAreTypedAndLeaveTheWorkspaceUntouched() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let good = signature([("a", "x", "int")])
        let before = cut(store)
        // Opposite of the type class: a data address and an address in no segment are not function entries.
        XCTAssertEqual(signatureFailure(store, shaped, good), "notFunctionEntry")
        XCTAssertEqual(signatureFailure(store, plain, good), "notFunctionEntry")
        XCTAssertEqual(signatureFailure(store, .primary(VerifiedAnnotationTestFixture.outside), good), "notFunctionEntry")
        XCTAssertEqual(signatureFailure(store, shaped, nil), "notFunctionEntry", "clearing is subject to the target rule too")
        // Non-canonical values: over the codec's byte, count and character bounds.
        let tooLongType = signature([("a", "x", String(repeating: "t", count: 513))])
        let tooLongName = signature([("a", String(repeating: "n", count: 257), "int")])
        let nulInType = signature([("a", "x", "i\0nt")])
        let nulReturn = signature([("a", "x", "int")], returnType: "v\0oid")
        let tooMany = signature((0..<65).map { ("t\($0)", "p\($0)", "int") })
        for (name, invalid) in [("long type", tooLongType), ("long name", tooLongName), ("NUL type", nulInType),
                                ("NUL return", nulReturn), ("65 parameters", tooMany)] {
            XCTAssertEqual(signatureFailure(store, entry, invalid), "invalidSignature", name)
        }
        XCTAssertEqual(cut(store), before)
        // A forced procedure start counts as a function entry even before reanalysis finds it.
        var forced = AddressOverride(markAsProcedure: true)
        forced.tag = "forced"
        store.applyOverride(shaped, forced, actionName: "fixture")
        XCTAssertNil(signatureFailure(store, shaped, good))
        // The type class keeps its own target rule: the same entry is refused there.
        XCTAssertEqual(stageFailure(store, entry, "Header"), "functionEntryTarget")
    }

    /// Ruling 5: parameter and return types are free text. Names with no `TypeDefinition` still stage.
    func testSignatureWithUnresolvedTypeNamesStages() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        XCTAssertFalse(store.snapshot.typeDefinitions.contains { $0.name == "NoSuchType_t" })
        let requested = signature([("a", "p", "NoSuchType_t *"), ("b", "n", "uint8_t")], returnType: "AlsoMissing")
        let candidate = try store.stageVerifiedSignature(at: entry, requested: requested)
        XCTAssertEqual(candidate.overrides[entry]?.signature, requested)
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(try XCTUnwrap(candidate.overrides[entry]?.signature)),
                       try VerifiedFieldCodec.canonicalSignature(requested))
    }

    /// Ruling 7, direction one: a rowToken-only change is a no-op for "observed equals requested".
    /// Direction two: it is still override drift for the protected members, through the erase rule.
    func testRowTokenOnlyChangeIsANoOpForReadbackButProtectedDriftElsewhere() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let old = signature([("old-1", "x", "int"), ("old-2", "y", "long")])
        let retokened = signature([("new-1", "x", "int"), ("new-2", "y", "long")])
        XCTAssertNotEqual(old, retokened, "ArgOverride equality includes rowToken")
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(old), try VerifiedFieldCodec.canonicalSignature(retokened))
        install(store, at: entry, old, authority: "session-authority")
        let before = cut(store)
        let candidate = try store.stageVerifiedSignature(at: entry, requested: retokened)
        XCTAssertEqual(cut(store), before)
        XCTAssertEqual(candidate.overrides[entry]?.signature, retokened, "the staged value is what was requested")
        XCTAssertNil(candidate.overrides[entry]?.ownReturnAuthorityFile, "a token change is a signature change for the didSet")
        // Direction two: the same token churn at another address is protected drift.
        install(store, at: .primary(0x1010), old)
        #if DEBUG
        store.verifiedAnnotationCandidateTestHook = {
            $0.overrides[.primary(0x1010)]?.signature = retokened
        }
        XCTAssertEqual(signatureFailure(store, entry, retokened), "protectedFieldMismatch")
        store.verifiedAnnotationCandidateTestHook = nil
        #endif
    }

    /// T10: the signature erase rule accepts only the `ownReturnAuthorityFile` reset as extra drift.
    func testSignatureEraseRuleAcceptsOnlyTheAuthorityResetAsExtraDrift() throws {
        let base = signature([("a", "x", "int")])
        let next = signature([("a", "x", "long")])
        // Accepted: a changed signature and the didSet reset of the authority, with nothing else.
        do {
            let store = VerifiedAnnotationTestFixture.typedStore()
            install(store, at: entry, base, authority: "session-authority")
            let candidate = try store.stageVerifiedSignature(at: entry, requested: next)
            XCTAssertNil(candidate.overrides[entry]?.ownReturnAuthorityFile)
        }
        #if DEBUG
        // Refused: any other authority value beside a signature change.
        do {
            let store = VerifiedAnnotationTestFixture.typedStore()
            install(store, at: entry, base, authority: "session-authority")
            let before = cut(store)
            store.verifiedAnnotationCandidateTestHook = { $0.overrides[self.entry]?.ownReturnAuthorityFile = "other-authority" }
            XCTAssertEqual(signatureFailure(store, entry, next), "protectedFieldMismatch", "a different authority is not the reset")
            XCTAssertEqual(cut(store), before)
        }
        // Refused: an authority change with no signature change at all (requested equals the live value).
        do {
            let store = VerifiedAnnotationTestFixture.typedStore()
            install(store, at: entry, base, authority: "session-authority")
            XCTAssertNil(signatureFailure(store, entry, base), "an identical signature keeps its authority and stages")
            store.verifiedAnnotationCandidateTestHook = { $0.overrides[self.entry]?.ownReturnAuthorityFile = "other-authority" }
            XCTAssertEqual(signatureFailure(store, entry, base), "protectedFieldMismatch")
            store.verifiedAnnotationCandidateTestHook = { $0.overrides[self.entry]?.ownReturnAuthorityFile = nil }
            XCTAssertEqual(signatureFailure(store, entry, base), "protectedFieldMismatch", "dropping the authority alone is drift")
        }
        // Refused: authority drift at another address, and any other protected member beside the signature.
        let others: [(String, (inout NativeAnnotationCandidate) -> Void)] = [
            ("authority elsewhere", { $0.overrides[.primary(0x1010)]?.ownReturnAuthorityFile = "collateral" }),
            ("signature elsewhere", { $0.overrides[.primary(0x1010)]?.signature = FunctionSignatureOverride(returnType: "void") }),
            ("tag", { $0.overrides[self.entry]?.tag = "collateral" }),
            ("applied type", { $0.overrides[self.entry]?.appliedTypeName = "Header" }),
            ("markAsProcedure at another address", { $0.overrides[.primary(0x1010)]?.markAsProcedure = true }),
        ]
        for (name, mutation) in others {
            let store = VerifiedAnnotationTestFixture.typedStore()
            install(store, at: entry, base, authority: "session-authority")
            install(store, at: .primary(0x1010), base, authority: "elsewhere")
            let before = cut(store)
            store.verifiedAnnotationCandidateTestHook = mutation
            let failure = signatureFailure(store, entry, next)
            XCTAssertTrue(failure == "protectedFieldMismatch" || failure == "candidateMismatch", "\(name): \(failure ?? "staged")")
            XCTAssertEqual(cut(store), before, name)
        }
        #endif
    }

    /// Ruling 6: the effective view returns the requested form, and an authoritative override wins over an
    /// imported prototype at the same address (Models/AnalysisModels+WorkspaceSnapshot.swift:1230-1239).
    func testEffectiveViewPrefersTheStagedSignatureOverAnImportedPrototype() throws {
        var snapshot = VerifiedAnnotationTestFixture.typedSnapshot()
        let imported = signature([("imp", "ignored", "double")], returnType: "double")
        snapshot.importedPrototypes[entry] = imported
        let store = WorkspaceStore(workspaceName: "Verified signatures", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        XCTAssertEqual(store.snapshot.functionSignatureOverrides(in: .primary)[entry.address], imported)
        let requested = signature([("req", "len", "size_t")], returnType: "int")
        let candidate = try store.stageVerifiedSignature(at: entry, requested: requested)
        var view = candidate.snapshot
        view.addressOverrides = candidate.overrides
        let effective = try XCTUnwrap(view.functionSignatureOverrides(in: .primary)[entry.address])
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(effective), try VerifiedFieldCodec.canonicalSignature(requested))
        XCTAssertNotEqual(try VerifiedFieldCodec.canonicalSignature(effective), try VerifiedFieldCodec.canonicalSignature(imported))
        // The live workspace still resolves the imported prototype: staging changed nothing.
        XCTAssertEqual(store.snapshot.functionSignatureOverrides(in: .primary)[entry.address], imported)
        // Clearing on the candidate falls back to the imported prototype.
        let cleared = try store.stageVerifiedSignature(at: entry, requested: nil)
        var clearedView = cleared.snapshot
        clearedView.addressOverrides = cleared.overrides
        XCTAssertEqual(clearedView.functionSignatureOverrides(in: .primary)[entry.address], imported)
    }
}
