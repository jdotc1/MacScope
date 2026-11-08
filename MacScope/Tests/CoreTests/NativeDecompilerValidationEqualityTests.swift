import Foundation
import XCTest
@testable import MacScope

final class NativeDecompilerValidationEqualityTests: XCTestCase {
    private let slot = ImageSlot(rawValue: 7)
    private let binaryID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    private let imageUUID = UUID(uuidString: "20000000-0000-0000-0000-000000000002")!
    private let functionID = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    private let requestID = UUID(uuidString: "40000000-0000-0000-0000-000000000004")!

    // Adapted synthetic fixtures from the supplied BuilderTests; all helpers are owned here.
    func testSelectedPatchChangesRequestAndUndoRestoresRawIdentity() throws {
        let original = try makeFixture(byteCount: 128).snapshot
        let baseline = try build(original)
        let baselineRequest = try requestProjection(baseline)
        var edited = original
        edited.addressOverrides[ImageAddress(slot: slot, address: 0x1004)] = .init(patch: .arm64NOP)
        let projected = try build(edited)
        XCTAssertEqual(projected.memoryRegions[0].rawBytes, baseline.memoryRegions[0].rawBytes)
        XCTAssertNotEqual(projected.memoryRegions[0].effectiveBytes, baseline.memoryRegions[0].effectiveBytes)
        XCTAssertEqual(projected.memoryRegions[0].appliedPatchIDs, ["patch000001"])
        XCTAssertNotEqual(try requestProjection(projected).requestSHA256, baselineRequest.requestSHA256)
        let codec = NativeDecompilerWireCodec()
        let request = try requestProjection(projected).makeRequestEnvelope(requestID: requestID)
        XCTAssertEqual(try codec.decodeRequest(codec.encodeRequest(request, matching: requestID),
                                               matching: requestID), request)
        edited.addressOverrides.removeValue(forKey: ImageAddress(slot: slot, address: 0x1004))
        XCTAssertEqual(try requestProjection(build(edited)), baselineRequest)
    }

    func testPatchedDirectBranchAdmitsOnlyCodeInsideSelectedFunction() throws {
        let original = try makeFixture(byteCount: 128, functionEnd: 0x1010).snapshot
        let baseline = try requestProjection(build(original))
        var edited = original
        // At 0x1004, ARM64 B +8 reaches 0x100c inside the selected
        // function's verified executable extent.
        edited.addressOverrides[ImageAddress(slot: slot, address: 0x1004)] = .init(
            patch: BytePatch(bytes: [0x02, 0x00, 0x00, 0x14])
        )
        let selected = try build(edited)
        XCTAssertEqual(selected.function.endAddressExclusive.value, 0x1010)
        XCTAssertNotEqual(try requestProjection(selected).requestSHA256, baseline.requestSHA256)
        XCTAssertEqual(selected.memoryRegions[0].appliedPatchIDs, ["patch000001"])

        // B +12 reaches 0x1010, outside the v3 selected-function contract.
        edited.addressOverrides[ImageAddress(slot: slot, address: 0x1004)] = .init(
            patch: BytePatch(bytes: [0x03, 0x00, 0x00, 0x14])
        )
        assertProjectionError(.patchedControlFlowLeavesFunction) { try build(edited) }
        edited.addressOverrides.removeValue(forKey: ImageAddress(slot: slot, address: 0x1004))
        // Even an in-range conditional target is insufficient when its
        // fall-through exits the selected interval.
        edited.addressOverrides[ImageAddress(slot: slot, address: 0x100c)] = .init(
            patch: BytePatch(bytes: [0x00, 0x00, 0x00, 0x54])
        )
        assertProjectionError(.patchedControlFlowLeavesFunction) { try build(edited) }
        edited.addressOverrides.removeValue(forKey: ImageAddress(slot: slot, address: 0x100c))
        XCTAssertEqual(try requestProjection(build(edited)), baseline)
    }


    func testContextOmissionManifestChangesRequestAndCacheIdentity() throws {
        let complete = try build(try makeContextFixture())
        var relocated = try makeContextFixture()
        relocated.mutateAnalysis(in: slot) { analysis in
            analysis.relocations = [RelocationSummary(id: UUID(), address: 0x101c,
                sectionName: "__const", typeCode: 0, typeName: nil, symbolName: nil,
                symbolIndex: nil, addend: nil, widthInBytes: 4)]
        }
        try refreshFingerprint(in: &relocated)
        let omitted = try build(relocated)
        XCTAssertTrue(complete.contextOmissions.isEmpty)
        XCTAssertFalse(omitted.contextOmissions.isEmpty)
        XCTAssertNotEqual(complete.contextOmissions.identitySHA256, omitted.contextOmissions.identitySHA256)
        XCTAssertNotEqual(try requestProjection(complete), try requestProjection(omitted))

        // Even with byte-identical wire content, a different omission set is a different request.
        let relabeled = NativeDecompilerSnapshotProjection(
            coordinate: complete.coordinate, target: complete.target, image: complete.image,
            function: complete.function, memoryRegions: complete.memoryRegions,
            symbols: complete.symbols, authoredInputs: complete.authoredInputs,
            contextOmissions: omitted.contextOmissions
        )
        let completeRequest = try requestProjection(complete)
        let relabeledRequest = try requestProjection(relabeled)
        XCTAssertEqual(completeRequest.requestSHA256, relabeledRequest.requestSHA256)
        XCTAssertNotEqual(completeRequest.contextOmissionSHA256, relabeledRequest.contextOmissionSHA256)
        XCTAssertNotEqual(completeRequest, relabeledRequest)
        XCTAssertEqual(try NativeDecompilerSubmission(snapshot: relabeled).projection.contextOmissions,
                       omitted.contextOmissions)
    }


    func testRejectsWrongSlotOwnerAndFunctionCoordinates() throws {
        let fixture = try makeFixture()
        assertProjectionError(.binaryNotFound) {
            try NativeDecompilerSnapshotBuilder.build(
                from: fixture.snapshot,
                imageSlot: ImageSlot(rawValue: 99),
                functionID: functionID,
                budgets: budgets
            )
        }

        var wrongOwner = fixture.snapshot
        var analysis = try XCTUnwrap(wrongOwner.analysis(in: slot))
        analysis.analysisInputFingerprint?.binaryID = UUID()
        wrongOwner.analysisBySlot[slot] = analysis
        assertProjectionError(.analysisCoordinateMismatch) { try build(wrongOwner) }

        var noAnalysis = fixture.snapshot
        noAnalysis.analysisBySlot = [:]
        assertProjectionError(.analysisNotFound) { try build(noAnalysis) }

        var duplicateOwner = fixture.snapshot
        duplicateOwner.binaries.append(duplicateOwner.binaries[0])
        assertProjectionError(.binaryNotFound) { try build(duplicateOwner) }

        assertProjectionError(.functionNotFound) {
            try NativeDecompilerSnapshotBuilder.build(
                from: fixture.snapshot,
                imageSlot: slot,
                functionID: UUID(),
                budgets: budgets
            )
        }

        var duplicateFunction = fixture.snapshot
        var duplicateAnalysis = try XCTUnwrap(duplicateFunction.analysis(in: slot))
        duplicateAnalysis.functions.append(duplicateAnalysis.functions[0])
        duplicateFunction.analysisBySlot[slot] = duplicateAnalysis
        try refreshFingerprint(in: &duplicateFunction)
        assertProjectionError(.functionNotFound) { try build(duplicateFunction) }
    }

    func testRejectsCurrentFunctionDriftFromStoredCompleteFingerprint() throws {
        let fixture = try makeFixture()

        var renamed = fixture.snapshot
        var renamedAnalysis = try XCTUnwrap(renamed.analysis(in: slot))
        renamedAnalysis.functions[0].name = "entry_after_stale_analysis"
        renamed.analysisBySlot[slot] = renamedAnalysis
        assertProjectionError(.analysisFingerprintMismatch) { try build(renamed) }

        var resized = fixture.snapshot
        var resizedAnalysis = try XCTUnwrap(resized.analysis(in: slot))
        resizedAnalysis.functions[0].endAddress = 0x100C
        resized.analysisBySlot[slot] = resizedAnalysis
        assertProjectionError(.analysisFingerprintMismatch) { try build(resized) }
    }

    func testRejectsTamperedStoredFacetAndOverallFingerprintDigests() throws {
        let fixture = try makeFixture()

        var facetTampered = fixture.snapshot
        var facetAnalysis = try XCTUnwrap(facetTampered.analysis(in: slot))
        var facetFingerprint = try XCTUnwrap(facetAnalysis.analysisInputFingerprint)
        let functionFacetIndex = try XCTUnwrap(
            facetFingerprint.facets.firstIndex { $0.kind == .functions }
        )
        facetFingerprint.facets[functionFacetIndex].sha256 = String(repeating: "1", count: 64)
        facetAnalysis.analysisInputFingerprint = facetFingerprint
        facetTampered.analysisBySlot[slot] = facetAnalysis
        assertProjectionError(.analysisFingerprintMismatch) { try build(facetTampered) }

        var overallTampered = fixture.snapshot
        var overallAnalysis = try XCTUnwrap(overallTampered.analysis(in: slot))
        overallAnalysis.analysisInputFingerprint?.overallSHA256 = String(repeating: "f", count: 64)
        overallTampered.analysisBySlot[slot] = overallAnalysis
        assertProjectionError(.analysisFingerprintMismatch) { try build(overallTampered) }
    }

    func testRejectsUnverifiedMissingIdentityUUIDLayoutAndFingerprint() throws {
        let fixture = try makeFixture()

        var unverified = fixture.snapshot
        unverified.binaries[0].artifactIntegrityState = .unavailable
        assertProjectionError(.unverifiedArtifact) { try build(unverified) }

        var noIdentity = fixture.snapshot
        noIdentity.binaries[0].artifactIdentity = nil
        assertProjectionError(.missingArtifactIdentity) { try build(noIdentity) }

        var noUUID = try makeFixture(uuid: nil).snapshot
        assertProjectionError(.missingArtifactUUID) { try build(noUUID) }
        noUUID.binaries[0].artifactIdentity = nil

        let zeroUUID = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
        assertProjectionError(.missingArtifactUUID) {
            try build(try makeFixture(uuid: zeroUUID).snapshot)
        }

        var noLayout = fixture.snapshot
        noLayout.binaries[0].preferredSegmentLayout = nil
        assertProjectionError(.missingSegmentLayout) { try build(noLayout) }

        var noFingerprint = fixture.snapshot
        var analysis = try XCTUnwrap(noFingerprint.analysis(in: slot))
        analysis.analysisInputFingerprint = nil
        noFingerprint.analysisBySlot[slot] = analysis
        assertProjectionError(.missingAnalysisFingerprint) { try build(noFingerprint) }
    }

    func testProjectsAcceptedArm64AndArm64eArtifactProfiles() throws {
        let arm64WithCapabilities = try build(
            try makeFixture(cpuSubtype: Int32(bitPattern: 0x8000_0000)).snapshot
        )
        XCTAssertEqual(arm64WithCapabilities.target.normalizedVariant, .arm64)
        XCTAssertEqual(arm64WithCapabilities.target.rawCPUSubtype, "80000000")
        XCTAssertEqual(arm64WithCapabilities.target.recognizedCapabilityBits, "80000000")
        XCTAssertNil(arm64WithCapabilities.target.pointerAuthABIVersion)

        let arm64e = try build(try makeFixture(cpuSubtype: 2).snapshot)
        XCTAssertEqual(arm64e.target.normalizedVariant, .arm64e)
        XCTAssertEqual(arm64e.target.rawCPUSubtype, "00000002")
        XCTAssertEqual(arm64e.target.recognizedCapabilityBits, "00000000")
        XCTAssertNil(arm64e.target.pointerAuthABIVersion)

        let arm64eV0 = try build(
            try makeFixture(cpuSubtype: Int32(bitPattern: 0x8000_0002)).snapshot
        )
        XCTAssertEqual(arm64eV0.target.normalizedVariant, .arm64e)
        XCTAssertEqual(arm64eV0.target.rawCPUSubtype, "80000002")
        XCTAssertEqual(arm64eV0.target.recognizedCapabilityBits, "80000000")
        XCTAssertEqual(arm64eV0.target.pointerAuthABIVersion, 0)
    }

    func testRejectsUnsupportedArm64SubtypeAndNonArm64Artifacts() throws {
        assertProjectionError(.unsupportedArchitecture) {
            try build(try makeFixture(cpuSubtype: 3).snapshot)
        }
        assertProjectionError(.unsupportedArchitecture) {
            try build(try makeFixture(cpuType: MachOConstants.cpuTypeX86_64, cpuSubtype: 3).snapshot)
        }
    }


    func testRejectsOverlappingLayouts() throws {

        let overlapping = [
            segment("__TEXT", vmStart: 0x1000, vmSize: 8, fileOffset: 0, fileSize: 8),
            segment("__DATA", vmStart: 0x1004, vmSize: 8, fileOffset: 8, fileSize: 4, protections: 3),
        ]
        assertProjectionError(.overlappingSegmentLayout) {
            try build(try makeFixture(byteCount: 12, segments: overlapping).snapshot)
        }

        let fileSpanOnlyOverlap = [
            segment("__T0", vmStart: 0x1000, vmSize: 4, fileOffset: 0, fileSize: 4),
            segment("__T1", vmStart: 0x2000, vmSize: 4, fileOffset: 2, fileSize: 4),
        ]
        assertProjectionError(.overlappingSegmentLayout) {
            try build(try makeFixture(
                byteCount: 6,
                segments: fileSpanOnlyOverlap,
                functionEnd: 0x1004
            ).snapshot)
        }
    }


    func testRejectsEmptyMismatchedAndOutOfRangeSelectedSliceEvidence() throws {
        let fixture = try makeFixture()

        var empty = fixture.snapshot
        var emptyAnalysis = try XCTUnwrap(empty.analysis(in: slot))
        emptyAnalysis.imageBytes = Data()
        empty.analysisBySlot[slot] = emptyAnalysis
        assertProjectionError(.emptySelectedSlice) { try build(empty) }

        var staleFingerprint = fixture.snapshot
        var staleAnalysis = try XCTUnwrap(staleFingerprint.analysis(in: slot))
        staleAnalysis.analysisInputFingerprint?.imageByteCount += 1
        staleFingerprint.analysisBySlot[slot] = staleAnalysis
        assertProjectionError(.selectedSliceMismatch) { try build(staleFingerprint) }

        var badArtifactHash = fixture.snapshot
        badArtifactHash.binaries[0].artifactIdentity = try MachOSliceArtifactIdentity(
            uuid: imageUUID,
            rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0,
            selectedSliceSHA256: String(repeating: "0", count: 64),
            selectedSliceByteCount: 32
        )
        try refreshFingerprint(in: &badArtifactHash)
        assertProjectionError(.selectedSliceMismatch) { try build(badArtifactHash) }

        let outOfRange = [
            segment("__TEXT", vmStart: 0x1000, vmSize: 8, fileOffset: 30, fileSize: 4),
        ]
        var outOfRangeFixture = try makeFixture(
            byteCount: 32,
            segments: outOfRange,
            functionEnd: 0x1004,
            layoutValidationByteCount: 64
        )
        try refreshFingerprint(in: &outOfRangeFixture.snapshot)
        assertProjectionError(.invalidSegmentLayout) { try build(outOfRangeFixture.snapshot) }
    }

    func testRejectsInvalidUnalignedAndOverBudgetFunctionRanges() throws {
        var invalid = try makeFixture().snapshot
        var analysis = try XCTUnwrap(invalid.analysis(in: slot))
        analysis.functions[0].endAddress = analysis.functions[0].startAddress
        invalid.analysisBySlot[slot] = analysis
        try refreshFingerprint(in: &invalid)
        assertProjectionError(.invalidFunctionRange) { try build(invalid) }

        var unaligned = try makeFixture().snapshot
        analysis = try XCTUnwrap(unaligned.analysis(in: slot))
        analysis.functions[0].startAddress += 1
        unaligned.analysisBySlot[slot] = analysis
        try refreshFingerprint(in: &unaligned)
        assertProjectionError(.invalidFunctionRange) { try build(unaligned) }

        let smallBudget = NativeDecompilerWireAnalysisBudgets(
            maxCodeBytes: 4,
            maxInstructions: 1,
            maxOperations: 1,
            maxOutputBytes: 1,
            maxWallTimeMilliseconds: .init(1)
        )
        assertProjectionError(.invalidBudgets) {
            try NativeDecompilerSnapshotBuilder.build(
                from: try makeFixture().snapshot,
                imageSlot: slot,
                functionID: functionID,
                budgets: smallBudget
            )
        }
    }

    func testMaterializesSelectedPatchAndRejectsPatchRangeOverflow() throws {
        var patched = try makeFixture().snapshot
        patched.addressOverrides[ImageAddress(slot: slot, address: 0x1004)] = AddressOverride(
            patch: .arm64NOP
        )
        let projection = try build(patched)
        XCTAssertEqual(projection.memoryRegions[0].appliedPatchIDs, ["patch000001"])
        XCTAssertNotEqual(projection.memoryRegions[0].rawBytes, projection.memoryRegions[0].effectiveBytes)

        var overflow = try makeFixture().snapshot
        overflow.addressOverrides[ImageAddress(slot: slot, address: UInt64.max - 1)] = AddressOverride(
            patch: .arm64NOP
        )
        assertProjectionError(.invalidPatchRange) { try build(overflow) }
    }

    func testRejectsIntersectingRelocationEvidenceButAllowsAdjacentRelocations() throws {
        let intersecting = RelocationSummary(
            id: UUID(),
            address: 0x1004,
            sectionName: "__TEXT,__text",
            typeCode: 2,
            typeName: "ARM64_RELOC_BRANCH26",
            symbolName: "_callee",
            symbolIndex: 1,
            addend: nil,
            isPCRelative: true,
            widthInBytes: 4
        )
        assertProjectionError(.intersectingRelocation) {
            try build(try makeFixture(relocations: [intersecting]).snapshot)
        }

        var adjacent = intersecting
        adjacent.address = 0x1020 // outside both the exact function and its actual mapped lookahead
        XCTAssertNoThrow(try build(try makeFixture(relocations: [adjacent]).snapshot))

        var unknownWidth = intersecting
        unknownWidth.widthInBytes = 0
        assertProjectionError(.intersectingRelocation) {
            try build(try makeFixture(relocations: [unknownWidth]).snapshot)
        }

        var overflowing = intersecting
        overflowing.address = UInt64.max - 1
        overflowing.widthInBytes = 4
        assertProjectionError(.invalidRelocationRange) {
            try build(try makeFixture(relocations: [overflowing]).snapshot)
        }
    }

    func testRequiresExactLoaderIssuedEffectiveByteIdentityAuthority() throws {
        var missing = try makeFixture().snapshot
        var missingAnalysis = try XCTUnwrap(missing.analysis(in: slot))
        missingAnalysis.identityEffectiveByteRanges = []
        missingAnalysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: try XCTUnwrap(missing.binaries.first),
            analysis: missingAnalysis
        )
        missing.analysisBySlot[slot] = missingAnalysis
        assertProjectionError(.effectiveLoadImageAuthorityUnavailable) { try build(missing) }

        var forged = try makeFixture().snapshot
        var analysis = try XCTUnwrap(forged.analysis(in: slot))
        let authority = try XCTUnwrap(analysis.identityEffectiveByteRanges.first)
        analysis.identityEffectiveByteRanges = [try IdentityEffectiveByteRangeAttestation(
            artifactIdentity: authority.artifactIdentity,
            segmentName: authority.segmentName,
            startAddress: authority.startAddress,
            endAddressExclusive: authority.endAddressExclusive,
            sliceRelativeFileOffset: authority.sliceRelativeFileOffset,
            byteCount: authority.byteCount,
            initialProtections: authority.initialProtections,
            rawBytesSHA256: String(repeating: "0", count: 64)
        )]
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: try XCTUnwrap(forged.binaries.first),
            analysis: analysis
        )
        forged.analysisBySlot[slot] = analysis
        assertProjectionError(.invalidEffectiveLoadImageAttestation) { try build(forged) }
    }


    func testRejectsInvalidBudgetsBeforeReadingWorkspaceEvidence() {
        let invalid = NativeDecompilerWireAnalysisBudgets(
            maxCodeBytes: 0,
            maxInstructions: 0,
            maxOperations: 0,
            maxOutputBytes: 0,
            maxWallTimeMilliseconds: .init(0)
        )
        assertProjectionError(.invalidBudgets) {
            try NativeDecompilerSnapshotBuilder.build(
                from: WorkspaceSnapshot(binaries: [], analysisBySlot: [:]),
                imageSlot: slot,
                functionID: functionID,
                budgets: invalid
            )
        }
    }

    func testT2T3FrozenRenamePatchLocalNameAndOrdinaryEquality() throws {
        let original = try makeFixture(byteCount: 128).snapshot
        _ = try build(original)
        var renamed = original
        renamed.addressOverrides[ImageAddress(slot: slot, address: 0x1000)] = .init(customName: "renamed")
        XCTAssertNotEqual(original.analysisGenerationID, renamed.analysisGenerationID)
        XCTAssertNotEqual(try build(original), try build(renamed))
        var patched = original
        patched.addressOverrides[ImageAddress(slot: slot, address: 0x1004)] = .init(patch: .arm64NOP)
        XCTAssertNotEqual(original.analysisGenerationID, patched.analysisGenerationID)
        _ = try build(patched)
        let words: [UInt32] = [0xd10083ff, 0xb9000be0, 0xb9400be1, 0x910083ff, 0xd65f03c0]
        var local = try makeFixture(functionEnd: 0x1014, instructionWords: words).snapshot
        local.addressOverrides[ImageAddress(slot: slot, address: 0x1000)] = .init(
            stackLocals: ["-24:-20": StackLocalOverride(name: "narrow_live", typeName: "uint32_t")])
        XCTAssertEqual(try build(local).authoredInputs.localNames.map(\.name), ["narrow_live"])
        var reanalyzed = original
        reanalyzed.mutateAnalysis(in: slot) { $0.functions[0].name = "new_analysis" }
        XCTAssertNotEqual(original.analysisGenerationID, reanalyzed.analysisGenerationID)
        assertProjectionError(.analysisFingerprintMismatch) { try build(reanalyzed) }
        try refreshFingerprint(in: &reanalyzed)
        _ = try build(reanalyzed)
    }

    func testT3AppendedCaveFullProjectionAndFixedRequestEquality() throws {
        let fixture = EqualityCaveFixture.makeSignedExecutableWithCommandSlack()
        // Load only the synthetic in-memory bytes. The URL labels provenance and is never opened.
        let loaded = try MachOBinaryLoader().load(bytes: fixture.bytes,
            sourceURL: URL(fileURLWithPath: "synthetic-signed-cave.macho"))
        let binary = BinaryImage(id: binaryID, name: loaded.name, path: loaded.path,
            kind: loaded.fileTypeName, architecture: loaded.architectureDisplayName,
            // captureOrigin is derived from this fact; without it the image is `.other` and the
            // appended-cave builder refuses (patchedControlFlowLeavesFunction).
            machOSelectedSliceFact: loaded.machOSelectedSliceFact,
            artifactIdentity: loaded.artifactIdentity, preferredSegmentLayout: loaded.preferredSegmentLayout,
            artifactIntegrityState: loaded.artifactIntegrityState,
            resolvedExecutablePath: loaded.resolvedExecutablePath, slot: slot)
        var analysis = ImageAnalysis(
            functions: [.init(id: functionID, name: "entry", startAddress: fixture.baseAddress,
                              endAddress: fixture.baseAddress + 4, confidence: 1)],
            sections: loaded.sections.map {
                SectionSummary(id: UUID(), name: $0.name, address: $0.address, size: $0.size,
                    fileOffset: $0.fileOffset, isExecutable: $0.isExecutable, isZeroFill: $0.isZeroFill)
            }, identityEffectiveByteRanges: loaded.identityEffectiveByteRanges, imageBytes: loaded.bytes)
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
        var snapshot = WorkspaceSnapshot(binaries: [binary], analysisBySlot: [slot: analysis])
        let raw = try build(snapshot)
        let authored = AppendedExecutableCaveAuthoring(ownerBinaryID: binary.id, functionID: functionID,
            selectedSliceSHA256: try XCTUnwrap(binary.artifactIdentity).selectedSliceSHA256,
            branchSourceAddress: fixture.baseAddress,
            codeBytes: Data([0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]))
        snapshot.addressOverrides[ImageAddress(slot: slot, address: fixture.baseAddress)] =
            AddressOverride(appendedExecutableCave: authored)
        let projection = try build(snapshot) // Full T3 oracle, including fixed-ID encoded bytes.
        let bound = try requestProjection(projection)
        XCTAssertEqual(bound.schemaVersion, NativeDecompilerWireRequestEnvelope.sparseCodeSchemaVersion)
        XCTAssertNotEqual(bound.requestSHA256, try requestProjection(raw).requestSHA256)
        let range = try XCTUnwrap(projection.function.codeRanges?.last)
        XCTAssertEqual(range.startAddress.value, 0x1_0000_c000)
        XCTAssertEqual(range.endAddressExclusive.value, 0x1_0000_c008)
        let region = try XCTUnwrap(projection.memoryRegions.first { $0.name == "__MSCAVE" })
        XCTAssertEqual(region.rawBytes.prefix(8), Data(repeating: 0, count: 8))
        XCTAssertEqual(region.effectiveBytes.prefix(8), authored.codeBytes)
        XCTAssertGreaterThanOrEqual(region.effectiveBytes.count, authored.codeBytes.count + 64)
        // T4: a recipe with an otherwise valid shape cannot bind to a different slice.
        snapshot.addressOverrides[ImageAddress(slot: slot, address: fixture.baseAddress)] =
            AddressOverride(appendedExecutableCave: AppendedExecutableCaveAuthoring(
                ownerBinaryID: binary.id, functionID: functionID, selectedSliceSHA256: String(repeating: "0", count: 64),
                branchSourceAddress: fixture.baseAddress, codeBytes: authored.codeBytes))
        assertProjectionError(.patchedControlFlowLeavesFunction) { try build(snapshot) }
    }

    func testT4SameValueDigestAndDualErrorPrecedence() throws {
        var snapshot = try makeFixture().snapshot
        snapshot.mutateAnalysis(in: slot) {
            $0.imageBytes[0] ^= 0xff
            $0.functions[0].name = "stale_facet_too"
        }
        // Reuse is sound only for analysis.imageBytes captured in this validateImage call:
        // changing that exact value must reject before the stale facet comparison.
        assertProjectionError(.selectedSliceMismatch) { try build(snapshot) }
        var xrefDrift = try makeFixture().snapshot
        xrefDrift.mutateAnalysis(in: slot) {
            $0.xrefs.append(.init(id: UUID(), from: 0x1000, to: 0x1010, kind: XRefKind.call))
        }
        assertProjectionError(.analysisFingerprintMismatch) { try build(xrefDrift) }
    }

    func testT9OneSliceDigestAndUnchangedSegmentDigestWork() throws {
        let snapshot = try makeFixture(byteCount: 128).snapshot
        let counts = ValidationDigestCounts()
        // Fixture identity/fingerprint setup is deliberately outside the observed interval.
        let validated = try NativeDecompilerSnapshotBuilder.validateImage(
            from: snapshot, imageSlot: slot,
            workObserver: .init(sliceDigestDidCompute: { counts.slice($0) },
                                segmentDigestDidCompute: { counts.segment($0) }))
        XCTAssertEqual(counts.slices, [128])
        // The attestation segment equals the slice here, but remains a separate hash category.
        XCTAssertEqual(counts.segments, [128])
        XCTAssertEqual(validated.fingerprint, snapshot.analysis(in: slot)?.analysisInputFingerprint)
    }

    func testT13TwoRequestCanonicalizationsRemainSeparateFromSliceDigest() throws {
        let snapshot = try makeFixture().snapshot
        // Build/validate outside the observed request-construction interval.
        let projection = try NativeDecompilerSnapshotBuilder.build(from: snapshot, imageSlot: slot,
            functionID: functionID, budgets: budgets)
        let sink = ValidationPhaseSink()
        let record = NativeDecompilerPhaseRecord(clock: { 100 }, sink: { sink.append($0) })
        _ = try NativeDecompilerPhaseRecord.withTrace(record) {
            let request = try NativeDecompilerRequestProjection(snapshotProjection: projection)
            return try NativeDecompilerPreencodedDispatchRequest(projection: request, requestID: requestID)
        }
        record.finish()
        XCTAssertEqual(sink.values.count, 1)
        XCTAssertEqual(sink.values[0].counts[NativeDecompilerPhaseRecord.Counter.canonicalPasses.rawValue], 2)
        XCTAssertEqual(sink.values[0].counts[NativeDecompilerPhaseRecord.Counter.sliceDigestPasses.rawValue], 0)
    }

    func testT13CodecStillChecksCanonicalBinding() throws {
        let projection = try requestProjection(build(makeFixture().snapshot))
        let original = projection.makeRequestEnvelope(requestID: requestID)
        let body = original.body
        let changed = NativeDecompilerWireRequest(requestID: requestID,
            requestSHA256: String(repeating: "f", count: 64), target: body.target,
            image: body.image, function: body.function, memoryRegions: body.memoryRegions,
            symbols: body.symbols, authoredInputs: body.authoredInputs, budgets: body.budgets)
        let forged = NativeDecompilerWireRequestEnvelope(schemaVersion: original.schemaVersion,
            requestID: requestID, operation: original.operation, body: changed)
        XCTAssertThrowsError(try NativeDecompilerWireCodec().encodeRequest(forged, matching: requestID)) {
            XCTAssertEqual($0 as? NativeDecompilerWireCodecError, .requestBindingMismatch)
        }
    }
}

private extension NativeDecompilerValidationEqualityTests {
    struct Fixture {
        var snapshot: WorkspaceSnapshot
    }

    var budgets: NativeDecompilerWireAnalysisBudgets {
        NativeDecompilerProductBudgetProfile.productDefault.wireValue
    }

    func build(_ snapshot: WorkspaceSnapshot) throws -> NativeDecompilerSnapshotProjection {
        let direct = try NativeDecompilerSnapshotBuilder.build(
            from: snapshot, imageSlot: slot, functionID: functionID, budgets: budgets)
        let validated = try NativeDecompilerSnapshotBuilder.validateImage(from: snapshot, imageSlot: slot)
        let captured = try NativeDecompilerSnapshotBuilder.build(
            from: snapshot, validatedImage: validated, functionID: functionID, budgets: budgets)
        XCTAssertEqual(direct, captured)
        XCTAssertEqual(direct.coordinate, captured.coordinate)
        XCTAssertEqual(direct.contextOmissions, captured.contextOmissions)
        let a = try NativeDecompilerSubmission(snapshot: direct).projection
        let b = try NativeDecompilerSubmission(snapshot: captured).projection
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.requestSHA256, b.requestSHA256)
        XCTAssertEqual(a.schemaVersion, b.schemaVersion)
        XCTAssertEqual(a.operation, b.operation)
        let encodedA = try NativeDecompilerPreencodedDispatchRequest(projection: a, requestID: requestID)
        let encodedB = try NativeDecompilerPreencodedDispatchRequest(projection: b, requestID: requestID)
        XCTAssertEqual(encodedA.envelope, encodedB.envelope)
        XCTAssertEqual(encodedA.payload, encodedB.payload)
        XCTAssertEqual(encodedA.expectedBinding, encodedB.expectedBinding)
        return direct
    }

    func requestProjection(
        _ snapshot: NativeDecompilerSnapshotProjection
    ) throws -> NativeDecompilerRequestProjection {
        try NativeDecompilerRequestProjection(snapshotProjection: snapshot)
    }

    func makeFixture(
        byteCount: Int = 32,
        segments: [MachOPreferredSegmentLayout.Record]? = nil,
        functionEnd: UInt64 = 0x1008,
        symbols: [SymbolSummary]? = nil,
        relocations: [RelocationSummary] = [],
        uuid: UUID? = UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
        cpuType: Int32 = MachOConstants.cpuTypeARM64,
        cpuSubtype: Int32 = 0,
        layoutValidationByteCount: UInt64? = nil,
        instructionWords: [UInt32]? = nil
    ) throws -> Fixture {
        let bytes = instructionWords.map { words in
            Data(words.flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) } })
        } ?? Data((0 ..< byteCount).map { UInt8(truncatingIfNeeded: $0) })
        let artifact = try MachOSliceArtifactIdentity(
            uuid: uuid,
            rawCPUType: cpuType,
            rawCPUSubtype: cpuSubtype,
            selectedSliceSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes),
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let records = segments ?? [
            segment(
                "__TEXT",
                vmStart: 0x1000,
                vmSize: UInt64(bytes.count),
                fileOffset: 0,
                fileSize: UInt64(bytes.count)
            ),
        ]
        let layout = try MachOPreferredSegmentLayout(
            records: records,
            selectedSliceByteCount: layoutValidationByteCount ?? UInt64(bytes.count)
        )
        let binary = BinaryImage(
            id: binaryID,
            name: "fixture",
            path: "/must/not/cross/the/projection",
            kind: "Mach-O 64-bit",
            architecture: "arm64",
            artifactIdentity: artifact,
            preferredSegmentLayout: layout,
            artifactIntegrityState: .verified,
            resolvedExecutablePath: "/also/must/not/cross",
            slot: slot
        )
        let function = FunctionSummary(
            id: functionID,
            name: "entry",
            startAddress: 0x1000,
            endAddress: functionEnd,
            confidence: 1
        )
        var analysis = ImageAnalysis(
            functions: [function],
            symbols: symbols ?? [
                SymbolSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000005")!,
                    name: "display-entry",
                    address: 0x1000,
                    kind: "export",
                    libraryName: nil,
                    rawLinkageName: "_entry"
                ),
                SymbolSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000006")!,
                    name: "duplicate-display-entry",
                    address: 0x1000,
                    kind: "export",
                    libraryName: nil,
                    rawLinkageName: "_entry"
                ),
                SymbolSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000007")!,
                    name: "display-only",
                    address: 0x1004,
                    kind: "local",
                    libraryName: nil,
                    rawLinkageName: nil
                ),
                SymbolSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000008")!,
                    name: "empty-raw",
                    address: 0x1004,
                    kind: "local",
                    libraryName: nil,
                    rawLinkageName: ""
                ),
                SymbolSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000009")!,
                    name: "mystery",
                    address: 0x1004,
                    kind: "loader-private",
                    libraryName: nil,
                    rawLinkageName: "_mystery"
                ),
            ],
            instructions: instructionWords == nil ? [] : ARM64Decoder().decode(bytes, baseAddress: 0x1000)
                .map { InstructionRow(decoded: $0) },
            relocations: relocations,
            identityEffectiveByteRanges: try makeIdentityEffectiveByteRanges(
                artifact: artifact,
                records: records,
                bytes: bytes
            ),
            imageBytes: bytes
        )
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        return Fixture(snapshot: WorkspaceSnapshot(
            binaries: [binary],
            analysisBySlot: [slot: analysis]
        ))
    }

    func segment(
        _ name: String,
        vmStart: UInt64,
        vmSize: UInt64,
        fileOffset: UInt64,
        fileSize: UInt64,
        protections: Int32 = 5
    ) -> MachOPreferredSegmentLayout.Record {
        MachOPreferredSegmentLayout.Record(
            name: name,
            preferredVMStart: vmStart,
            preferredVMSize: vmSize,
            sliceRelativeFileOffset: fileOffset,
            fileSize: fileSize,
            initialProtections: protections
        )
    }

    func refreshFingerprint(in snapshot: inout WorkspaceSnapshot) throws {
        let binary = try XCTUnwrap(snapshot.binary(in: slot))
        var analysis = try XCTUnwrap(snapshot.analysis(in: slot))
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        snapshot.analysisBySlot[slot] = analysis
    }

    func refreshArtifactAndFingerprint(in snapshot: inout WorkspaceSnapshot) throws {
        var binary = try XCTUnwrap(snapshot.binary(in: slot))
        var analysis = try XCTUnwrap(snapshot.analysis(in: slot))
        let artifact = try MachOSliceArtifactIdentity(
            uuid: imageUUID,
            rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0,
            selectedSliceSHA256: AnalysisFingerprintBuilder.sha256Hex(analysis.imageBytes),
            selectedSliceByteCount: UInt64(analysis.imageBytes.count)
        )
        binary.artifactIdentity = artifact
        analysis.identityEffectiveByteRanges = try makeIdentityEffectiveByteRanges(
            artifact: artifact,
            records: try XCTUnwrap(binary.preferredSegmentLayout).records,
            bytes: analysis.imageBytes
        )
        snapshot.binaries[0] = binary
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        snapshot.analysisBySlot[slot] = analysis
    }

    func makeIdentityEffectiveByteRanges(
        artifact: MachOSliceArtifactIdentity,
        records: [MachOPreferredSegmentLayout.Record],
        bytes: Data
    ) throws -> [IdentityEffectiveByteRangeAttestation] {
        try records.compactMap { record in
            guard record.fileSize > 0,
                  record.initialProtections & 1 != 0,
                  record.initialProtections & 2 == 0 else {
                return nil
            }
            let end = record.sliceRelativeFileOffset.addingReportingOverflow(record.fileSize)
            let virtualEnd = record.preferredVMStart.addingReportingOverflow(record.fileSize)
            guard !end.overflow,
                  !virtualEnd.overflow,
                  end.partialValue <= UInt64(bytes.count),
                  let lower = Int(exactly: record.sliceRelativeFileOffset),
                  let upper = Int(exactly: end.partialValue) else {
                return nil
            }
            return try IdentityEffectiveByteRangeAttestation(
                artifactIdentity: artifact,
                segmentName: record.name,
                startAddress: record.preferredVMStart,
                endAddressExclusive: virtualEnd.partialValue,
                sliceRelativeFileOffset: record.sliceRelativeFileOffset,
                byteCount: record.fileSize,
                initialProtections: record.initialProtections,
                rawBytesSHA256: AnalysisFingerprintBuilder.sha256Hex(
                    bytes.subdata(in: lower..<upper)
                )
            )
        }
    }

    func makeContextFixture(dataProtections: Int32 = 1) throws -> WorkspaceSnapshot {
        var snapshot = try makeFixture(segments: [
            segment("__TEXT", vmStart: 0x1000, vmSize: 24, fileOffset: 0, fileSize: 24),
            segment("__CONST", vmStart: 0x1018, vmSize: 8, fileOffset: 24, fileSize: 8, protections: dataProtections),
        ]).snapshot
        var analysis = try XCTUnwrap(snapshot.analysis(in: slot))
        analysis.functions += [
            .init(id: UUID(), name: "callee", startAddress: 0x1008, endAddress: 0x1010, confidence: 1),
            .init(id: UUID(), name: "unrelated", startAddress: 0x1010, endAddress: 0x1018, confidence: 1),
        ]
        analysis.xrefs = [
            .init(id: UUID(), from: 0x1000, to: 0x1008, kind: XRefKind.call),
            .init(id: UUID(), from: 0x1004, to: 0x1018, kind: XRefKind.data),
        ]
        snapshot.analysisBySlot[slot] = analysis
        try refreshFingerprint(in: &snapshot)
        return snapshot
    }

    func assertProjectionError(
        _ expected: NativeDecompilerSnapshotProjectionError,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ operation: () throws -> NativeDecompilerSnapshotProjection
    ) {
        do {
            _ = try operation()
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch let error as NativeDecompilerSnapshotProjectionError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("Unexpected error: \(error)", file: file, line: line)
        }
    }
}

private final class ValidationDigestCounts: @unchecked Sendable {
    private let lock = NSLock()
    private var sliceBytes: [Int] = []
    private var segmentBytes: [Int] = []
    var slices: [Int] { lock.withLock { sliceBytes } }
    var segments: [Int] { lock.withLock { segmentBytes } }
    func slice(_ bytes: Int) { lock.withLock { sliceBytes.append(bytes) } }
    func segment(_ bytes: Int) { lock.withLock { segmentBytes.append(bytes) } }
}

private final class ValidationPhaseSink: @unchecked Sendable {
    private let lock = NSLock()
    private var summaries: [NativeDecompilerPhaseRecord.Summary] = []
    var values: [NativeDecompilerPhaseRecord.Summary] { lock.withLock { summaries } }
    func append(_ value: NativeDecompilerPhaseRecord.Summary) { lock.withLock { summaries.append(value) } }
}

// Owned copies of supplement fixtures; no private helper from another test is referenced.
private struct EqualityCaveFixture {
    var bytes: Data
    var code: Data
    var codeOffset: Int
    var baseAddress: UInt64
    static func makeExecutable(code: Data = Data([
            0xff, 0x83, 0x00, 0xd1,
            0xfd, 0x7b, 0x01, 0xa9,
            0xfd, 0x43, 0x00, 0x91,
            0x00, 0x01, 0x40, 0xf9,
            0x00, 0x01, 0x00, 0xf9,
            0x00, 0x00, 0x80, 0x52,
            0x01, 0x00, 0x00, 0x94,
            0xc0, 0x03, 0x5f, 0xd6
        ]),
        cpuType: Int32 = MachOConstants.cpuTypeARM64,
        cpuSubtype: Int32 = 0
    ) -> EqualityCaveFixture {
        let headerSize = 32
        let segmentCommandSize = 72 + 80
        let mainCommandSize = 24
        let loadCommandsSize = segmentCommandSize + mainCommandSize
        let codeOffset = headerSize + loadCommandsSize
        let imageBase = 0x1_0000_0000 as UInt64
        let codeAddress = imageBase + UInt64(codeOffset)
        let textFileSize = UInt64(codeOffset + code.count)

        var bytes = Data()
        append32(0xfeedfacf, to: &bytes)
        append32(UInt32(bitPattern: cpuType), to: &bytes)
        append32(UInt32(bitPattern: cpuSubtype), to: &bytes)
        append32(MachOConstants.fileTypeExecute, to: &bytes)
        append32(2, to: &bytes)
        append32(UInt32(loadCommandsSize), to: &bytes)
        append32(0, to: &bytes)
        append32(0, to: &bytes)

        append32(MachOConstants.loadCommandSegment64, to: &bytes)
        append32(UInt32(segmentCommandSize), to: &bytes)
        appendName("__TEXT", to: &bytes)
        append64(imageBase, to: &bytes)
        append64(textFileSize, to: &bytes)
        append64(0, to: &bytes)
        append64(textFileSize, to: &bytes)
        append32(5, to: &bytes)
        append32(5, to: &bytes)
        append32(1, to: &bytes)
        append32(0, to: &bytes)

        appendName("__text", to: &bytes)
        appendName("__TEXT", to: &bytes)
        append64(codeAddress, to: &bytes)
        append64(UInt64(code.count), to: &bytes)
        append32(UInt32(codeOffset), to: &bytes)
        append32(2, to: &bytes)
        append32(0, to: &bytes)
        append32(0, to: &bytes)
        append32(MachOConstants.sectionAttributePureInstructions
                 | MachOConstants.sectionAttributeSomeInstructions, to: &bytes)
        append32(0, to: &bytes)
        append32(0, to: &bytes)
        append32(0, to: &bytes)

        append32(MachOConstants.loadCommandMain, to: &bytes)
        append32(UInt32(mainCommandSize), to: &bytes)
        append64(UInt64(codeOffset), to: &bytes)
        append64(0, to: &bytes)

        precondition(bytes.count == codeOffset)
        bytes.append(code)

        return EqualityCaveFixture(bytes: bytes, code: code, codeOffset: codeOffset, baseAddress: codeAddress)
    }

    static func makeSignedExecutableWithCommandSlack() -> EqualityCaveFixture {
        var fixture = makeExecutable()
        let oldOffset = fixture.codeOffset
        let textOffset = 0x4000
        fixture.bytes.insert(contentsOf: repeatElement(0, count: textOffset - oldOffset), at: oldOffset)
        let base: UInt64 = 0x1_0000_0000
        write64(0x8000, into: &fixture.bytes, at: 64) // __TEXT vmsize
        write64(UInt64(textOffset + fixture.code.count), into: &fixture.bytes, at: 80)
        write64(base + UInt64(textOffset), into: &fixture.bytes, at: 136)
        write32(UInt32(textOffset), into: &fixture.bytes, at: 152)
        write64(UInt64(textOffset), into: &fixture.bytes, at: 192) // LC_MAIN entryoff
        fixture.codeOffset = textOffset
        fixture.baseAddress = base + UInt64(textOffset)

        // The only new load commands are a final sectionless __LINKEDIT and
        // LC_CODE_SIGNATURE. The signature blob occupies the last 256 bytes.
        var linkCommand = Data()
        append32(MachOConstants.loadCommandSegment64, to: &linkCommand)
        append32(72, to: &linkCommand)
        appendName("__LINKEDIT", to: &linkCommand)
        append64(base + 0x8000, to: &linkCommand)
        append64(0x4000, to: &linkCommand)
        append64(0x8000, to: &linkCommand)
        append64(0x100, to: &linkCommand)
        append32(1, to: &linkCommand)
        append32(1, to: &linkCommand)
        append32(0, to: &linkCommand)
        append32(0, to: &linkCommand)
        fixture.bytes.replaceSubrange(208..<280, with: linkCommand)
        var signatureCommand = Data()
        append32(MachOConstants.loadCommandCodeSignature, to: &signatureCommand)
        append32(16, to: &signatureCommand)
        append32(0x8000, to: &signatureCommand)
        append32(0x100, to: &signatureCommand)
        fixture.bytes.replaceSubrange(280..<296, with: signatureCommand)
        var uuidCommand = Data()
        append32(MachOConstants.loadCommandUUID, to: &uuidCommand)
        append32(24, to: &uuidCommand)
        uuidCommand.append(contentsOf: (1...16).map(UInt8.init))
        fixture.bytes.replaceSubrange(296..<320, with: uuidCommand)
        write32(5, into: &fixture.bytes, at: 16)
        write32(288, into: &fixture.bytes, at: 20)
        fixture.bytes.append(contentsOf: repeatElement(0, count: 0x8000 - fixture.bytes.count))
        fixture.bytes.append(contentsOf: repeatElement(0x5a, count: 0x100))
        return fixture
    }

    private static func read32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
    }

    private static func append32(_ value: UInt32, to data: inout Data) {
        for index in 0..<4 { data.append(UInt8(truncatingIfNeeded: value >> (index * 8))) }
    }

    private static func append64(_ value: UInt64, to data: inout Data) {
        for index in 0..<8 { data.append(UInt8(truncatingIfNeeded: value >> (index * 8))) }
    }

    private static func appendName(_ value: String, to data: inout Data) {
        data.append(contentsOf: value.utf8)
        data.append(contentsOf: repeatElement(0, count: 16 - value.utf8.count))
    }

    private static func write32(_ value: UInt32, into data: inout Data, at offset: Int) {
        for index in 0..<4 { data[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    }

    private static func write64(_ value: UInt64, into data: inout Data, at offset: Int) {
        for index in 0..<8 { data[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    }

}
