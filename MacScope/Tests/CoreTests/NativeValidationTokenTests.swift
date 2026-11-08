import Foundation
import XCTest
@testable import MacScope

// Item 1312, pin ec7378046184c6d5cc579a1539d15f9691926d79.
// Static authoring only: not compiled or run. Land only WITH WIRING A01-A05.
// No refresh helper runs after an edit; each dependency case has one write.
#if DEBUG
@MainActor
final class NativeValidationTokenTests: XCTestCase {
    // Constants and fixture copied from input 6:8-11,509-612.
    private let functionID = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    private let binaryID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    private let secondID = UUID(uuidString: "30000000-0000-0000-0000-000000000004")!
    private let thirdID = UUID(uuidString: "30000000-0000-0000-0000-000000000005")!

    func testNativeValidationAuthoringAddressOverride() async throws {
        // T-A1-ADDRESS-OVERRIDE
        let signature = FunctionSignatureOverride(returnType: "int",
            parameterList: .authoritative([ArgOverride(name: "value", type: "int")]),
            variadicState: .fixed, noReturnState: .returns)
        try await assertAuthoringSurvival("T-A1-ADDRESS-OVERRIDE") {
            $0.addressOverrides[ImageAddress(slot: .primary, address: 0x1000)] =
                AddressOverride(customName: "renamed_entry", customComment: "authored comment", signature: signature)
        }
    }

    func testNativeValidationAuthoringImportedPrototype() async throws {
        // T-A1-IMPORTED-PROTOTYPE
        let signature = FunctionSignatureOverride(returnType: "int",
            parameterList: .authoritative([ArgOverride(name: "value", type: "int")]),
            variadicState: .fixed, noReturnState: .returns)
        try await assertAuthoringSurvival("T-A1-IMPORTED-PROTOTYPE") {
            $0.importedPrototypes[ImageAddress(slot: .primary, address: 0x1000)] = signature
        }
    }

    func testNativeValidationAuthoringTypeDefinition() async throws {
        // T-A1-TYPE-DEFINITION
        let definition = populatedTypeDefinition()
        try await assertAuthoringSurvival("T-A1-TYPE-DEFINITION") { $0.typeDefinitions = [definition] }
    }

    func testNativeValidationAuthoringHeaderEvidence() async throws {
        // T-A1-HEADER-EVIDENCE: empty input always exercises public-generation renewal.
        try await assertAuthoringSurvival("T-A1-HEADER-EVIDENCE-empty") { $0.recordHeaderImportEvidence([]) }
        // Populated branch: setup is BEFORE first capture. Only recordHeaderImportEvidence
        // is the measured edit. The private evidence dictionary is not inspected.
        let existing = populatedTypeDefinition()
        var declaration = existing
        declaration.id = UUID()
        XCTAssertNotEqual(declaration.id, existing.id)
        var comparable = declaration
        comparable.id = existing.id
        XCTAssertEqual(comparable, existing)
        var original = try makeScriptingFixture()
        original.typeDefinitions = [existing]
        try await assertAuthoringSurvival("T-A1-HEADER-EVIDENCE-populated", original: original) {
            $0.recordHeaderImportEvidence([declaration])
        }
    }

    func testNativeValidationAuthoringPatchOverride() async throws {
        // T-A1-PATCH-OVERRIDE: authoring only, no reanalysis/byte replacement.
        try await assertAuthoringSurvival("T-A1-PATCH-OVERRIDE") {
            $0.addressOverrides[ImageAddress(slot: .primary, address: 0x1000)] =
                AddressOverride(patch: BytePatch(bytes: [0x1f, 0x20, 0x03, 0xd5]))
        }
    }

    func testNativeValidationV1DuplicateBinary() async throws {
        // T-A2-V1
        try await assertRelevantWrite("T-A2-V1") { snapshot in
            let binary = snapshot.binaries[0]
            snapshot.binaries.append(binary)
        }
    }

    func testNativeValidationV2RemoveAnalysis() async throws {
        // T-A2-V2
        try await assertRelevantWrite("T-A2-V2") { snapshot in
            snapshot.analysisBySlot[.primary] = nil
        }
    }

    func testNativeValidationV3ArtifactIntegrity() async throws {
        // T-A2-V3
        try await assertRelevantWrite("T-A2-V3") { snapshot in
            snapshot.binaries[0].artifactIntegrityState = .unavailable
        }
    }

    func testNativeValidationV4ArtifactIdentity() async throws {
        // T-A2-V4
        try await assertRelevantWrite("T-A2-V4") { snapshot in
            snapshot.binaries[0].artifactIdentity = nil
        }
    }

    func testNativeValidationV5SegmentLayout() async throws {
        // T-A2-V5
        try await assertRelevantWrite("T-A2-V5") { snapshot in
            snapshot.binaries[0].preferredSegmentLayout = nil
        }
    }

    func testNativeValidationV6StoredFingerprint() async throws {
        // T-A2-V6
        try await assertRelevantWrite("T-A2-V6") { snapshot in
            snapshot.analysisBySlot[.primary]?.analysisInputFingerprint = nil
        }
    }

    func testNativeValidationV7SelectedSliceByte() async throws {
        // T-A2-V7
        try await assertRelevantWrite("T-A2-V7") { snapshot in
            snapshot.analysisBySlot[.primary]?.imageBytes[0] = 1
        }
    }

    func testNativeValidationV8FunctionCount() async throws {
        // T-A2-V8
        try await assertRelevantWrite("T-A2-V8") { snapshot in
            snapshot.analysisBySlot[.primary]?.functions.removeLast()
        }
    }

    func testNativeValidationV9Attestations() async throws {
        // T-A2-V9
        try await assertRelevantWrite("T-A2-V9") { snapshot in
            snapshot.analysisBySlot[.primary]?.identityEffectiveByteRanges = []
        }
    }

    func testNativeValidationV10SymbolProjection() async throws {
        // T-A2-V10
        try await assertRelevantWrite("T-A2-V10") { snapshot in
            snapshot.analysisBySlot[.primary]?.symbols = [SymbolSummary(id: UUID(), name: "symbol", address: 0x1000,
                kind: "export", libraryName: nil, rawLinkageName: "_symbol")]
        }
    }

    func testNativeValidationV11RetainedFunctionID() async throws {
        // T-A2-V11
        try await assertRelevantWrite("T-A2-V11") { snapshot in
            let function = snapshot.functions[1]
            snapshot.analysisBySlot[.primary]?.functions[1] = FunctionSummary(id: UUID(), name: function.name,
                startAddress: function.startAddress, endAddress: function.endAddress, confidence: function.confidence)
        }
    }

    func testNativeValidationF2LoaderSection() async throws {
        // T-A2-F2
        try await assertRelevantWrite("T-A2-F2") { snapshot in
            snapshot.analysisBySlot[.primary]?.sections[0].name = "changed"
        }
    }

    func testNativeValidationF3CodeDataRanges() async throws {
        // T-A2-F3
        try await assertRelevantWrite("T-A2-F3") { snapshot in
            snapshot.analysisBySlot[.primary]?.codeDataRanges = [CodeDataRangeSummary(id: UUID(), address: 0x1000, size: 4, kind: "data")]
        }
    }

    func testNativeValidationF4AttestationFacet() async throws {
        // T-A2-F4
        try await assertRelevantWrite("T-A2-F4") { snapshot in
            snapshot.analysisBySlot[.primary]?.identityEffectiveByteRanges = []
        }
    }

    func testNativeValidationF5InstructionFacet() async throws {
        // T-A2-F5
        try await assertRelevantWrite("T-A2-F5") { snapshot in
            snapshot.analysisBySlot[.primary]?.instructions[0].mnemonic = "changed"
        }
    }

    func testNativeValidationF6BinaryMetadata() async throws {
        // T-A2-F6
        try await assertRelevantWrite("T-A2-F6") { snapshot in
            snapshot.binaries[0].metadata.buildTools.append("changed")
        }
    }

    func testNativeValidationF7ControlFlow() async throws {
        // T-A2-F7
        try await assertRelevantWrite("T-A2-F7") { snapshot in
            snapshot.analysisBySlot[.primary]?.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: 0x1000, to: 0x1004, kind: "flow")]
        }
    }

    func testNativeValidationF8XRefs() async throws {
        // T-A2-F8
        try await assertRelevantWrite("T-A2-F8") { snapshot in
            snapshot.analysisBySlot[.primary]?.xrefs = [XRef(id: UUID(), from: 0x1000, to: 0x1008, kind: XRefKind.call)]
        }
    }

    func testNativeValidationF9SourceLines() async throws {
        // T-A2-F9
        try await assertRelevantWrite("T-A2-F9") { snapshot in
            snapshot.analysisBySlot[.primary]?.sourceLines = [SourceLineEntry(address: 0x1000, file: "synthetic.c", line: 1, column: 1, endSequence: false)]
        }
    }

    func testNativeValidationF10BinaryPath() async throws {
        // T-A2-F10
        try await assertRelevantWrite("T-A2-F10") { snapshot in
            snapshot.binaries[0].path = "changed-synthetic-path"
        }
    }

    func testNativeValidationControlA02BinariesOnly() async throws {
        // CTL-A02-BINARIES-ONLY; EQUAL-VALUE-WRITE-BINARIES.
        // T-A2-NEW-VALIDATION-COUNT; T-A2-ID-BEFORE-REFRESH representative.
        try await assertRelevantWrite("CTL-A02-BINARIES-ONLY") { snapshot in
            let binaries = snapshot.binaries
            snapshot.binaries = binaries
        }
    }

    func testNativeValidationControlA03Subscript() async throws {
        // CTL-A03-SUBSCRIPT; EQUAL-VALUE-WRITE-ANALYSIS (whole dictionary equality write).
        try await assertRelevantWrite("CTL-A03-SUBSCRIPT") { snapshot in
            let analysis = snapshot.analysisBySlot[.primary]
            snapshot.analysisBySlot[.primary] = analysis
        }
        try await assertRelevantWrite("EQUAL-VALUE-WRITE-ANALYSIS") { snapshot in
            let analysis = snapshot.analysisBySlot
            snapshot.analysisBySlot = analysis
        }
    }

    func testNativeValidationControlA03EmptyMutateAnalysis() async throws {
        // CTL-A03-MUTATE-ANALYSIS: the closure is deliberately empty.
        try await assertRelevantWrite("CTL-A03-MUTATE-ANALYSIS") { snapshot in
            snapshot.mutateAnalysis(in: .primary) { _ in }
        }
    }

    func testNativeValidationControlA03FlatSetter() async throws {
        // CTL-A03-FLAT-SETTER
        try await assertRelevantWrite("CTL-A03-FLAT-SETTER") { snapshot in
            let functions = snapshot.functions
            snapshot.functions = functions
        }
    }

    func testNativeValidationControlA03ReplaceAnalysis() async throws {
        // CTL-A03-REPLACE-ANALYSIS
        let original = try makeScriptingFixture()
        let bucket = try XCTUnwrap(original.analysis(in: .primary))
        try await assertRelevantWrite("CTL-A03-REPLACE-ANALYSIS", original: original) { snapshot in
            snapshot.replaceAnalysis(bucket, in: .primary)
        }
    }

    func testNativeValidationUnrelatedAnalysisWrite() async throws {
        // UNRELATED-ANALYSIS-WRITE: diagnostic assignment is outside validator facets;
        // its element type is not supplied, so use the evidenced empty array assignment.
        try await assertRelevantWrite("UNRELATED-ANALYSIS-WRITE") { snapshot in
            snapshot.diagnostics = []
        }
    }

    func testNativeValidationCopyRollbackAndFreshConstruction() throws {
        let original = try makeScriptingFixture()
        let native = original.nativeImageValidationGenerationID
        // COPY-PLAIN
        let copy = original
        XCTAssertEqual(copy.nativeImageValidationGenerationID, native)
        // COPY-MUTATED
        var edited = copy
        edited.analysisBySlot[.primary]?.imageBytes[0] = 1
        XCTAssertNotEqual(edited.nativeImageValidationGenerationID, native)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native)
        XCTAssertEqual(copy.nativeImageValidationGenerationID, native)
        XCTAssertEqual(original.imageBytes.first, 0)
        XCTAssertEqual(copy.imageBytes.first, 0)
        XCTAssertEqual(edited.imageBytes.first, 1)
        // COPY-ROLLBACK
        edited = original
        XCTAssertEqual(edited.nativeImageValidationGenerationID, native)
        XCTAssertEqual(edited.imageBytes, original.imageBytes)
        XCTAssertEqual(edited.analysisGenerationID, original.analysisGenerationID)
        // FRESH-SAME-INPUTS: two executions of the image-scoped initializer.
        let first = WorkspaceSnapshot(binaries: original.binaries, analysisBySlot: original.analysisBySlot)
        let second = WorkspaceSnapshot(binaries: original.binaries, analysisBySlot: original.analysisBySlot)
        XCTAssertNotEqual(first.nativeImageValidationGenerationID, native)
        XCTAssertNotEqual(second.nativeImageValidationGenerationID, native)
        XCTAssertNotEqual(first.nativeImageValidationGenerationID, second.nativeImageValidationGenerationID)
        XCTAssertEqual(first.binaries, original.binaries)
        XCTAssertEqual(first.imageBytes, original.imageBytes)
        XCTAssertEqual(first.analysisInputFingerprint, original.analysisInputFingerprint)
        // The other initializer also executes private stored-property initialization.
        let legacyFirst = WorkspaceSnapshot(binaries: original.binaries, functions: original.functions,
            basicBlocks: original.basicBlocks, instructions: original.instructions, xrefs: original.xrefs,
            hexBytes: original.hexBytes, sections: original.sections,
            identityEffectiveByteRanges: original.identityEffectiveByteRanges,
            imageBytes: original.imageBytes, analysisInputFingerprint: original.analysisInputFingerprint)
        let legacySecond = WorkspaceSnapshot(binaries: original.binaries, functions: original.functions,
            basicBlocks: original.basicBlocks, instructions: original.instructions, xrefs: original.xrefs,
            hexBytes: original.hexBytes, sections: original.sections,
            identityEffectiveByteRanges: original.identityEffectiveByteRanges,
            imageBytes: original.imageBytes, analysisInputFingerprint: original.analysisInputFingerprint)
        XCTAssertNotEqual(legacyFirst.nativeImageValidationGenerationID, native)
        XCTAssertNotEqual(legacyFirst.nativeImageValidationGenerationID, legacySecond.nativeImageValidationGenerationID)
        XCTAssertEqual(legacyFirst.binaries, original.binaries)
        XCTAssertEqual(legacyFirst.imageBytes, original.imageBytes)
        XCTAssertEqual(legacyFirst.analysisInputFingerprint, original.analysisInputFingerprint)
    }

    func testNativeValidationFreshWireRoundtrip() throws {
        // FRESH-WIRE-ROUNDTRIP. Codec use copied from input 7:191-205 only.
        // No encoded-byte/text search and no persistence-format claim.
        let original = try makeScriptingFixture()
        let codec = PayloadWireCodec()
        let encoded = codec.encodeReply(.success(original))
        let first = try codec.decodeReply(encoded)
        let second = try codec.decodeReply(encoded, pinnedSource: nil)
        XCTAssertNotEqual(first.nativeImageValidationGenerationID, original.nativeImageValidationGenerationID)
        XCTAssertNotEqual(second.nativeImageValidationGenerationID, original.nativeImageValidationGenerationID)
        XCTAssertNotEqual(first.nativeImageValidationGenerationID, second.nativeImageValidationGenerationID)
        XCTAssertNotEqual(first.analysisGenerationID, original.analysisGenerationID)
        XCTAssertNotEqual(second.analysisGenerationID, original.analysisGenerationID)
        XCTAssertEqual(first.analysis(in: .primary)?.imageBytes, original.analysis(in: .primary)?.imageBytes)
        XCTAssertEqual(second.analysis(in: .primary)?.imageBytes, original.analysis(in: .primary)?.imageBytes)
    }

    private func populatedTypeDefinition() -> TypeDefinition {
        TypeDefinition(kind: .struct, name: "NativeValidationRecord",
            fields: [FieldDef(name: "value", type: "int")])
    }

    private func assertAuthoringSurvival(_ id: String, original supplied: WorkspaceSnapshot? = nil,
                                         edit: (inout WorkspaceSnapshot) -> Void) async throws {
        let original = try supplied ?? makeScriptingFixture()
        let native = original.nativeImageValidationGenerationID
        let publicID = original.analysisGenerationID
        let work = NativeValidationWork()
        let store = NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { work.enter() }))
        let fence = NativeDecompilerAdmissionFence()
        let token = try XCTUnwrap(fence.advance())
        let registryID = UUID()
        let owner = UUID()
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: original, imageSlot: .primary, admissionToken: token)
        var edited = original
        edit(&edited)
        XCTAssertEqual(edited.nativeImageValidationGenerationID, native, id)
        // INDEPENDENCE-PUBLIC-GENERATION: every authoring category, not one proxy.
        XCTAssertNotEqual(edited.analysisGenerationID, publicID, id)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native, id)
        XCTAssertEqual(original.analysisGenerationID, publicID, id)
        XCTAssertEqual(edited.binaries, original.binaries, id)
        XCTAssertEqual(edited.imageBytes, original.imageBytes, id)
        XCTAssertEqual(edited.analysisInputFingerprint, original.analysisInputFingerprint, id)
        let reused = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: edited, imageSlot: .primary, admissionToken: token)
        // T-A1-COUNT-ONE-VALIDATION: both attempts and completed validations.
        XCTAssertEqual(work.attempts, 1, id)
        let completed = await store.validationCount()
        XCTAssertEqual(completed, 1, id)
        let freshWork = NativeValidationWork()
        let freshStore = NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { freshWork.enter() }))
        let fresh = try await freshStore.captureForScripting(registryID: registryID, owner: owner,
            snapshot: edited, imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(freshWork.attempts, 1, id)
        let freshCompleted = await freshStore.validationCount()
        XCTAssertEqual(freshCompleted, 1, id)
        // T-A1-FRESH-EQUALS-REUSED: whole projection or exact typed build refusal,
        // and whole encoded envelope after binding the same fixed request UUID.
        try assertImageAndProjectionEqual(reused, fresh, snapshot: edited, id: id)
    }

    private func assertRelevantWrite(_ id: String, original supplied: WorkspaceSnapshot? = nil,
                                     edit: (inout WorkspaceSnapshot) -> Void) async throws {
        let original = try supplied ?? makeScriptingFixture()
        let untouched = original
        // Frozen value witnesses captured before the edit, not old-copy-vs-old-copy comparisons.
        let oldBinaries = original.binaries
        let oldBytes = original.imageBytes
        let oldFunctions = original.functions
        let oldSymbols = original.symbols
        let oldXRefs = original.xrefs
        let oldSections = original.sections
        let oldFingerprint = original.analysisInputFingerprint
        let oldAttestations = original.identityEffectiveByteRanges
        let oldInstructions = original.instructions
        let oldCodeDataRanges = original.codeDataRanges
        let oldEdges = original.controlFlowEdges
        let oldSourceLines = original.sourceLines
        let native = original.nativeImageValidationGenerationID
        let publicID = original.analysisGenerationID
        let work = NativeValidationWork()
        let store = NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { work.enter() }))
        let fence = NativeDecompilerAdmissionFence()
        let token = try XCTUnwrap(fence.advance())
        let registryID = UUID()
        let owner = UUID()
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: original, imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(work.attempts, 1, id)
        let beforeCompleted = await store.validationCount()
        XCTAssertEqual(beforeCompleted, 1, id)
        var edited = original
        edit(&edited)
        // FIRST assertion after the single indicated write. No refresh before or after.
        XCTAssertNotEqual(edited.nativeImageValidationGenerationID, native, id)
        XCTAssertEqual(untouched.nativeImageValidationGenerationID, native, id)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native, id)
        // INDEPENDENCE-PUBLIC-GENERATION also covers every relevant-write route.
        XCTAssertNotEqual(edited.analysisGenerationID, publicID, id)
        XCTAssertEqual(untouched.analysisGenerationID, publicID, id)
        XCTAssertEqual(untouched.binaries, oldBinaries, id)
        XCTAssertEqual(original.binaries, oldBinaries, id)
        XCTAssertEqual(untouched.imageBytes, oldBytes, id)
        XCTAssertEqual(original.imageBytes, oldBytes, id)
        XCTAssertEqual(untouched.functions, oldFunctions, id)
        XCTAssertEqual(original.functions, oldFunctions, id)
        XCTAssertEqual(untouched.symbols, oldSymbols, id)
        XCTAssertEqual(original.symbols, oldSymbols, id)
        XCTAssertEqual(untouched.xrefs, oldXRefs, id)
        XCTAssertEqual(original.xrefs, oldXRefs, id)
        XCTAssertEqual(untouched.sections, oldSections, id)
        XCTAssertEqual(original.sections, oldSections, id)
        XCTAssertEqual(untouched.analysisInputFingerprint, oldFingerprint, id)
        XCTAssertEqual(original.analysisInputFingerprint, oldFingerprint, id)
        XCTAssertEqual(original.identityEffectiveByteRanges, oldAttestations, id)
        XCTAssertEqual(original.instructions, oldInstructions, id)
        XCTAssertEqual(original.codeDataRanges, oldCodeDataRanges, id)
        XCTAssertEqual(original.controlFlowEdges, oldEdges, id)
        XCTAssertEqual(original.sourceLines, oldSourceLines, id)
        let reused = try await captureOutcome {
            try await store.captureForScripting(registryID: registryID, owner: owner,
                snapshot: edited, imageSlot: .primary, admissionToken: token)
        }
        XCTAssertEqual(work.attempts, 2, id)
        let freshWork = NativeValidationWork()
        let freshStore = NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { freshWork.enter() }))
        let fresh = try await captureOutcome {
            try await freshStore.captureForScripting(registryID: registryID, owner: owner,
                snapshot: edited, imageSlot: .primary, admissionToken: token)
        }
        XCTAssertEqual(freshWork.attempts, 1, id)
        let completed = await store.validationCount()
        let freshCompleted = await freshStore.validationCount()
        switch (reused, fresh) {
        case let (.success(a), .success(b)):
            XCTAssertEqual(completed, 2, id)
            XCTAssertEqual(freshCompleted, 1, id)
            try assertImageAndProjectionEqual(a, b, snapshot: edited, id: id)
        case let (.failure(a), .failure(b)):
            XCTAssertEqual(a, b, id) // exact typed refusal, never merely "both throw"
            XCTAssertEqual(completed, 1, id) // refused attempt did not complete
            XCTAssertEqual(freshCompleted, 0, id)
        default:
            XCTFail("\(id): reused capture and fresh capture disagree on success/refusal")
        }
    }

    private func captureOutcome(_ capture: () async throws -> NativeDecompilerSnapshotBuilder.ValidatedImage)
        async throws -> Result<NativeDecompilerSnapshotBuilder.ValidatedImage, NativeDecompilerSnapshotProjectionError> {
        do { return .success(try await capture()) }
        catch let error as NativeDecompilerSnapshotProjectionError { return .failure(error) }
        catch { throw error } // Unknown errors fail the test instead of comparing nil casts.
    }

    private func projectionOutcome(_ image: NativeDecompilerSnapshotBuilder.ValidatedImage,
                                   snapshot: WorkspaceSnapshot)
        throws -> Result<NativeDecompilerSnapshotProjection, NativeDecompilerSnapshotProjectionError> {
        do {
            return .success(try NativeDecompilerSnapshotBuilder.build(from: snapshot, validatedImage: image,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets))
        } catch let error as NativeDecompilerSnapshotProjectionError { return .failure(error) }
        catch { throw error }
    }

    private func assertImageAndProjectionEqual(_ reused: NativeDecompilerSnapshotBuilder.ValidatedImage,
                                              _ fresh: NativeDecompilerSnapshotBuilder.ValidatedImage,
                                              snapshot: WorkspaceSnapshot, id: String) throws {
        // Selected retained state compared directly, so build's recheck cannot hide stale state.
        XCTAssertEqual(reused.imageSlot, fresh.imageSlot, id)
        XCTAssertEqual(reused.binaryID, fresh.binaryID, id)
        XCTAssertEqual(reused.selectedSliceBytes, fresh.selectedSliceBytes, id)
        XCTAssertEqual(reused.byteCount, fresh.byteCount, id)
        XCTAssertEqual(reused.byteSHA256, fresh.byteSHA256, id)
        XCTAssertEqual(reused.fingerprint, fresh.fingerprint, id)
        XCTAssertEqual(reused.artifactUUID, fresh.artifactUUID, id)
        XCTAssertEqual(reused.rawCPUType, fresh.rawCPUType, id)
        XCTAssertEqual(reused.functionsByID, fresh.functionsByID, id)
        XCTAssertEqual(reused.functionsByStart, fresh.functionsByStart, id)
        XCTAssertEqual(reused.sortedXRefs, fresh.sortedXRefs, id)
        XCTAssertEqual(reused.relocations, fresh.relocations, id)
        XCTAssertEqual(reused.mappedLayout.map { $0.record }, fresh.mappedLayout.map { $0.record }, id)
        XCTAssertEqual(reused.attestationErrors, fresh.attestationErrors, id)
        XCTAssertEqual(reused.preferredLoadAddress, fresh.preferredLoadAddress, id)
        let reusedProjection = try projectionOutcome(reused, snapshot: snapshot)
        let freshProjection = try projectionOutcome(fresh, snapshot: snapshot)
        XCTAssertEqual(reusedProjection, freshProjection, id)
        if case let .success(a) = reusedProjection, case let .success(b) = freshProjection {
            let reusedEnvelope = try NativeDecompilerRequestProjection(snapshotProjection: a)
                .makeRequestEnvelope(requestID: UUID())
            let freshEnvelope = try NativeDecompilerRequestProjection(snapshotProjection: b)
                .makeRequestEnvelope(requestID: UUID())
            XCTAssertEqual(try fixedPayload(reusedEnvelope), try fixedPayload(freshEnvelope), id)
        }
    }

    private func fixedPayload(_ envelope: NativeDecompilerWireRequestEnvelope) throws -> Data {
        let id = UUID(uuidString: "40000000-0000-0000-0000-000000000004")!
        let rebound = NativeDecompilerRequestProjection(request: envelope.body, operation: envelope.operation)
            .makeRequestEnvelope(requestID: id)
        return try NativeDecompilerWireCodec().encodeRequest(rebound, matching: id)
    }

    private func makeScriptingFixture(byteCount: Int = 128, xrefCount: Int = 0) throws -> WorkspaceSnapshot {
        let bytes = Data(repeating: 0, count: byteCount)
        let artifact = try MachOSliceArtifactIdentity(
            uuid: UUID(uuidString: "30000000-0000-0000-0000-000000000003")!,
            rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0,
            selectedSliceSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes),
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let layout = try MachOPreferredSegmentLayout(
            records: [
                .init(
                    name: "__TEXT",
                    preferredVMStart: 0x1000,
                    preferredVMSize: UInt64(bytes.count),
                    sliceRelativeFileOffset: 0,
                    fileSize: UInt64(bytes.count),
                    initialProtections: 5
                ),
            ],
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let binary = BinaryImage(
            id: binaryID,
            name: "fixture",
            path: "synthetic-fixture",
            kind: "Mach-O 64-bit",
            architecture: "arm64",
            artifactIdentity: artifact,
            preferredSegmentLayout: layout,
            artifactIntegrityState: .verified,
            slot: .primary
        )
        var analysis = ImageAnalysis(
            functions: [
                FunctionSummary(
                    id: functionID,
                    name: "entry",
                    startAddress: 0x1000,
                    endAddress: 0x1008,
                    confidence: 1
                ),
            ],
            basicBlocks: [
                BasicBlockSummary(
                    id: UUID(),
                    functionID: functionID,
                    startAddress: 0x1000,
                    endAddress: 0x1008,
                    instructionCount: 2
                ),
            ],
            instructions: [
                InstructionRow(
                    address: 0x1000,
                    bytes: "1f 20 03 d5",
                    mnemonic: "nop",
                    operands: "",
                    hasBreakpoint: false,
                    comment: nil
                ),
                InstructionRow(
                    address: 0x1004,
                    bytes: "c0 03 5f d6",
                    mnemonic: "ret",
                    operands: "",
                    hasBreakpoint: false,
                    comment: nil
                ),
            ],
            sections: [
                SectionSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000005")!,
                    name: "__TEXT,__text",
                    address: 0x1000,
                    size: UInt64(bytes.count),
                    fileOffset: 0,
                    isExecutable: true
                ),
            ],
            identityEffectiveByteRanges: [try IdentityEffectiveByteRangeAttestation(
                artifactIdentity: artifact,
                segmentName: "__TEXT",
                startAddress: 0x1000,
                endAddressExclusive: 0x1000 + UInt64(bytes.count),
                sliceRelativeFileOffset: 0,
                byteCount: UInt64(bytes.count),
                initialProtections: 5,
                rawBytesSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes)
            )],
            imageBytes: bytes
        )
        analysis.functions += [
            .init(id: secondID, name: "second", startAddress: 0x1008, endAddress: 0x1010, confidence: 1),
            .init(id: thirdID, name: "third", startAddress: 0x1010, endAddress: 0x1018, confidence: 1)]
        analysis.xrefs = (0..<xrefCount).map { _ in
            .init(id: UUID(), from: 0xf0000000, to: 0xf0000004, kind: XRefKind.call)
        }
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }
}

// Counter shape copied from input 6:615-621; each store has a separate counter.
private final class NativeValidationWork: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = 0
    var attempts: Int { lock.withLock { stored } }
    func enter() { lock.withLock { stored += 1 } }
}
#endif
