import Foundation
import XCTest
@testable import MacScope

// Item 1324 (M5 token follow-on A01-A06), test-only residual coverage.
// Complements NativeValidationTokenTests / NativeValidationTokenCoverageTests /
// NativeValidationTypeShapeTests, which are not replayed here. Self-contained: no helper
// of another file is called. No refresh helper runs after any edit; every route test asserts
// the native-validation inequality immediately after its single API call or property write.
#if DEBUG
@MainActor
final class NativeDecompilerTokenFollowOnTests: XCTestCase {
    private let functionID = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    private let binaryID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    private let secondID = UUID(uuidString: "30000000-0000-0000-0000-000000000004")!
    private let thirdID = UUID(uuidString: "30000000-0000-0000-0000-000000000005")!
    private let remappedSlot = ImageSlot(rawValue: 7)
    private let entryKey = ImageAddress(slot: .primary, address: 0x1000)

    // MARK: - DR03 / DR04 / DR05: image routes

    func testInsertImageRenewsNativeID() throws {
        let original = try makeFixture()
        // Vacancy and the copied binary/bucket are prepared BEFORE the original is frozen.
        XCTAssertNil(original.binary(in: remappedSlot))
        XCTAssertNil(original.analysis(in: remappedSlot))
        var second = original.binaries[0]
        second.slot = remappedSlot
        let bucket = try XCTUnwrap(original.analysis(in: .primary))
        let untouched = original
        let native = original.nativeImageValidationGenerationID
        let publicID = original.analysisGenerationID
        let oldBinaries = original.binaries
        let oldCount = original.binaries.count

        var edited = original
        edited.insertImage(binary: second, analysis: bucket)
        // FIRST assertion after the single API call.
        XCTAssertNotEqual(edited.nativeImageValidationGenerationID, native)
        XCTAssertEqual(untouched.nativeImageValidationGenerationID, native)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native)
        XCTAssertNotEqual(edited.analysisGenerationID, publicID)
        XCTAssertEqual(original.analysisGenerationID, publicID)
        XCTAssertEqual(original.binaries, oldBinaries)
        XCTAssertNil(original.binary(in: remappedSlot))
        XCTAssertNil(original.analysis(in: remappedSlot))
        XCTAssertEqual(edited.binaries.count - oldCount, 1)
        XCTAssertEqual(edited.binaries.last, second)
        XCTAssertEqual(edited.binary(in: remappedSlot), second)
        assertSameBucket(try XCTUnwrap(edited.analysis(in: remappedSlot)), bucket)
        assertSameBucket(try XCTUnwrap(edited.analysis(in: .primary)), bucket)
    }

    func testRemoveImageRenewsNativeIDAndRefusesFresh() async throws {
        let original = try makeFixture()
        let untouched = original
        let native = original.nativeImageValidationGenerationID
        let publicID = original.analysisGenerationID
        let oldBinaries = original.binaries
        let work = FollowOnWork()
        let store = makeStore(work)
        let token = try XCTUnwrap(NativeDecompilerAdmissionFence().advance())
        let registryID = UUID()
        let owner = UUID()
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: original, imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(work.attempts, 1)
        let retainedBefore = await store.captureCount()
        XCTAssertEqual(retainedBefore, 1)

        var edited = original
        edited.removeImage(in: .primary)
        // FIRST assertion after the single API call.
        XCTAssertNotEqual(edited.nativeImageValidationGenerationID, native)
        XCTAssertEqual(untouched.nativeImageValidationGenerationID, native)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native)
        XCTAssertNotEqual(edited.analysisGenerationID, publicID)
        XCTAssertEqual(original.analysisGenerationID, publicID)
        XCTAssertEqual(original.binaries, oldBinaries)
        XCTAssertTrue(edited.binaries.isEmpty)
        XCTAssertNil(edited.analysisBySlot[.primary])

        // The retained entry for the old native token is never returned.
        let reusedError = try await refusal { try await store.captureForScripting(
            registryID: registryID, owner: owner, snapshot: edited,
            imageSlot: .primary, admissionToken: token) }
        XCTAssertEqual(reusedError, .binaryNotFound)
        XCTAssertEqual(work.attempts, 2)
        let completed = await store.validationCount()
        XCTAssertEqual(completed, 1)
        let retainedAfter = await store.captureCount()
        XCTAssertEqual(retainedAfter, 0)

        let freshWork = FollowOnWork()
        let freshStore = makeStore(freshWork)
        let freshError = try await refusal { try await freshStore.captureForScripting(
            registryID: registryID, owner: owner, snapshot: edited,
            imageSlot: .primary, admissionToken: token) }
        XCTAssertEqual(freshError, .binaryNotFound)
        XCTAssertEqual(freshWork.attempts, 1)
        let freshCompleted = await freshStore.validationCount()
        XCTAssertEqual(freshCompleted, 0)
    }

    func testRemapImageSlotRenewsNativeIDAndPreservesSameSlot() throws {
        // Authoring is seeded in setup, before the original is frozen.
        var original = try makeFixture()
        let prototype = FunctionSignatureOverride(returnType: "int", parameterList: .authoritative([]),
            variadicState: .fixed, noReturnState: .returns)
        let override = AddressOverride(customName: "renamed_entry", customComment: "authored comment")
        original.addressOverrides[entryKey] = override
        original.importedPrototypes[entryKey] = prototype
        XCTAssertNil(original.binary(in: remappedSlot))
        XCTAssertNil(original.analysis(in: remappedSlot))
        let bucket = try XCTUnwrap(original.analysis(in: .primary))
        let untouched = original
        let native = original.nativeImageValidationGenerationID
        let publicID = original.analysisGenerationID
        let oldBinaries = original.binaries

        // Changed-slot route (compound: several observed writes inside one API call).
        var moved = original
        moved.remapImageSlot(from: .primary, to: remappedSlot)
        XCTAssertNotEqual(moved.nativeImageValidationGenerationID, native)
        XCTAssertEqual(untouched.nativeImageValidationGenerationID, native)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native)
        XCTAssertNotEqual(moved.analysisGenerationID, publicID)
        XCTAssertEqual(original.analysisGenerationID, publicID)
        XCTAssertEqual(original.binaries, oldBinaries)
        XCTAssertEqual(moved.binaries.map(\.slot), [remappedSlot])
        XCTAssertNil(moved.analysisBySlot[.primary])
        assertSameBucket(try XCTUnwrap(moved.analysis(in: remappedSlot)), bucket)
        let newKey = ImageAddress(slot: remappedSlot, address: 0x1000)
        XCTAssertNil(moved.addressOverrides[entryKey])
        XCTAssertEqual(moved.addressOverrides[newKey], override)
        XCTAssertNil(moved.importedPrototypes[entryKey])
        XCTAssertEqual(moved.importedPrototypes[newKey], prototype)

        // Same-slot route: no write at all, so nothing is renewed and nothing moves.
        var same = original
        same.remapImageSlot(from: .primary, to: .primary)
        XCTAssertEqual(same.nativeImageValidationGenerationID, native)
        XCTAssertEqual(same.analysisGenerationID, publicID)
        XCTAssertEqual(same.binaries, oldBinaries)
        assertSameBucket(try XCTUnwrap(same.analysis(in: .primary)), bucket)
        XCTAssertEqual(same.addressOverrides[entryKey], override)
        XCTAssertEqual(same.importedPrototypes[entryKey], prototype)
    }

    // MARK: - DR06 / DR07: capture count

    func testCaptureCountTracksRetainedOwner() async throws {
        let original = try makeFixture()
        let work = FollowOnWork()
        let store = makeStore(work)
        let token = try XCTUnwrap(NativeDecompilerAdmissionFence().advance())
        let registryID = UUID()
        let owner = UUID()

        // (captureCount, validationCount, attempts)
        func triple() async -> [Int] {
            let retained = await store.captureCount()
            let completed = await store.validationCount()
            return [retained, completed, work.attempts]
        }
        let initial = await triple()
        XCTAssertEqual(initial, [0, 0, 0])

        // Fixture eligibility is a prerequisite, not a result: a failure here is a fixture failure.
        let analysis = try XCTUnwrap(original.analysis(in: .primary))
        XCTAssertTrue(NativeDecompilerScriptingCaptureKey.permitsRetention(
            functions: analysis.functions.count, xrefs: analysis.xrefs.count,
            relocations: analysis.relocations.count, symbols: analysis.symbols.count))
        let first = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: original, imageSlot: .primary, admissionToken: token)
        XCTAssertTrue(first.retainedBytes <= 64 * 1_048_576)
        let afterFirst = await triple()
        XCTAssertEqual(afterFirst, [1, 1, 1])

        // Authoring-only write: native survives, so the retained entry is reused.
        var authored = original
        authored.addressOverrides[entryKey] = AddressOverride(customName: "renamed_entry",
                                                              customComment: "authored comment")
        XCTAssertEqual(authored.nativeImageValidationGenerationID, original.nativeImageValidationGenerationID)
        XCTAssertNotEqual(authored.analysisGenerationID, original.analysisGenerationID)
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: authored, imageSlot: .primary, admissionToken: token)
        let afterAuthoring = await triple()
        XCTAssertEqual(afterAuthoring, [1, 1, 1])

        // Equal-value binaries write: native is renewed before anything else, one more validation,
        // and the same owner's entry is replaced rather than added.
        var rewritten = authored
        let binaries = rewritten.binaries
        rewritten.binaries = binaries
        XCTAssertNotEqual(rewritten.nativeImageValidationGenerationID, authored.nativeImageValidationGenerationID)
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: rewritten, imageSlot: .primary, admissionToken: token)
        let afterRewrite = await triple()
        XCTAssertEqual(afterRewrite, [1, 2, 2])

        // Removing the sole image: the miss drops the entry and the refusal never inserts.
        var removed = rewritten
        removed.removeImage(in: .primary)
        XCTAssertNotEqual(removed.nativeImageValidationGenerationID, rewritten.nativeImageValidationGenerationID)
        let error = try await refusal { try await store.captureForScripting(
            registryID: registryID, owner: owner, snapshot: removed,
            imageSlot: .primary, admissionToken: token) }
        XCTAssertEqual(error, .binaryNotFound)
        let afterRemoval = await triple()
        XCTAssertEqual(afterRemoval, [0, 2, 3])
    }

    func testCaptureCountDistinguishesUnretainedValidation() async throws {
        let original = try makeFixture()
        let work = FollowOnWork()
        let store = makeStore(work)
        let token = try XCTUnwrap(NativeDecompilerAdmissionFence().advance())
        let key = NativeDecompilerScriptingCaptureKey(registryID: UUID(), scriptingOwner: UUID(),
            snapshot: original, imageSlot: .primary)
        let image = try await store.capture(owner: key.scriptingOwner,
            revision: key.nativeImageValidationGenerationID, snapshot: original, imageSlot: .primary,
            admissionToken: token, scriptingKey: key, permitsRetention: false)
        XCTAssertEqual(image.imageSlot, .primary)
        let retained = await store.captureCount()
        let completed = await store.validationCount()
        XCTAssertEqual([retained, completed, work.attempts], [0, 1, 1])
    }

    // MARK: - DR08 / DR09: key and store conjuncts

    func testScriptingKeyBindsEachAuthorityField() {
        let snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        let registryA = binaryID, registryB = functionID
        let ownerA = secondID, ownerB = thirdID
        let base = NativeDecompilerScriptingCaptureKey(registryID: registryA, scriptingOwner: ownerA,
            snapshot: snapshot, imageSlot: .primary)
        XCTAssertEqual(base.registryID, registryA)
        XCTAssertEqual(base.scriptingOwner, ownerA)
        XCTAssertEqual(base.imageSlot, .primary)
        XCTAssertEqual(base.nativeImageValidationGenerationID, snapshot.nativeImageValidationGenerationID)

        XCTAssertNotEqual(base, NativeDecompilerScriptingCaptureKey(registryID: registryB,
            scriptingOwner: ownerA, snapshot: snapshot, imageSlot: .primary))
        XCTAssertNotEqual(base, NativeDecompilerScriptingCaptureKey(registryID: registryA,
            scriptingOwner: ownerB, snapshot: snapshot, imageSlot: .primary))
        XCTAssertNotEqual(base, NativeDecompilerScriptingCaptureKey(registryID: registryA,
            scriptingOwner: ownerA, snapshot: snapshot, imageSlot: remappedSlot))
        // Only the native token differs: an equal-value binaries write renews it.
        var renewed = snapshot
        let binaries = renewed.binaries
        renewed.binaries = binaries
        XCTAssertNotEqual(renewed.nativeImageValidationGenerationID, snapshot.nativeImageValidationGenerationID)
        let renewedKey = NativeDecompilerScriptingCaptureKey(registryID: registryA, scriptingOwner: ownerA,
            snapshot: renewed, imageSlot: .primary)
        XCTAssertEqual(renewedKey.nativeImageValidationGenerationID, renewed.nativeImageValidationGenerationID)
        XCTAssertNotEqual(base, renewedKey)

        // A plain copy and an authoring-only write keep the native token, so the key is equal.
        let copy = snapshot
        XCTAssertEqual(base, NativeDecompilerScriptingCaptureKey(registryID: registryA,
            scriptingOwner: ownerA, snapshot: copy, imageSlot: .primary))
        var authored = snapshot
        authored.addressOverrides[entryKey] = AddressOverride(customName: "renamed_entry")
        XCTAssertNotEqual(authored.analysisGenerationID, snapshot.analysisGenerationID)
        XCTAssertEqual(base, NativeDecompilerScriptingCaptureKey(registryID: registryA,
            scriptingOwner: ownerA, snapshot: authored, imageSlot: .primary))
    }

    func testStoreHitRequiresRevisionAndScriptingKey() async throws {
        let original = try makeFixture()
        let work = FollowOnWork()
        let store = makeStore(work)
        let token = try XCTUnwrap(NativeDecompilerAdmissionFence().advance())
        let owner = UUID()
        let key = NativeDecompilerScriptingCaptureKey(registryID: UUID(), scriptingOwner: owner,
            snapshot: original, imageSlot: .primary)
        let otherKey = NativeDecompilerScriptingCaptureKey(registryID: UUID(), scriptingOwner: owner,
            snapshot: original, imageSlot: .primary)
        XCTAssertNotEqual(key, otherKey)
        let revision = key.nativeImageValidationGenerationID
        let otherRevision = UUID()
        XCTAssertNotEqual(revision, otherRevision)

        func capture(revision: UUID, key: NativeDecompilerScriptingCaptureKey) async throws {
            _ = try await store.capture(owner: owner, revision: revision, snapshot: original,
                imageSlot: .primary, admissionToken: token, scriptingKey: key)
        }
        func counts() async -> [Int] {
            let completed = await store.validationCount()
            return [completed, work.attempts]
        }
        try await capture(revision: revision, key: key)
        let retained = await store.captureCount()
        XCTAssertEqual(retained, 1) // retention premise for every hit below
        var observed = await counts()
        XCTAssertEqual(observed, [1, 1])
        try await capture(revision: revision, key: key) // same revision and key: hit
        observed = await counts()
        XCTAssertEqual(observed, [1, 1])
        try await capture(revision: otherRevision, key: key) // only the revision differs
        observed = await counts()
        XCTAssertEqual(observed, [2, 2])
        try await capture(revision: otherRevision, key: key) // the replacement entry now hits
        observed = await counts()
        XCTAssertEqual(observed, [2, 2])
        try await capture(revision: otherRevision, key: otherKey) // only the scripting key differs
        observed = await counts()
        XCTAssertEqual(observed, [3, 3])
        try await capture(revision: otherRevision, key: otherKey)
        observed = await counts()
        XCTAssertEqual(observed, [3, 3])
    }

    // MARK: - DR10: literal refusals

    func testRelevantWriteRefusalsHaveLiteralCases() async throws {
        try await assertRefusal("duplicate-binary", .binaryNotFound) { snapshot in
            let binary = snapshot.binaries[0]
            snapshot.binaries.append(binary)
        }
        try await assertRefusal("remove-bucket", .analysisNotFound) { snapshot in
            snapshot.analysisBySlot[.primary] = nil
        }
        try await assertRefusal("integrity-unavailable", .unverifiedArtifact) { snapshot in
            snapshot.binaries[0].artifactIntegrityState = .unavailable
        }
        try await assertRefusal("artifact-nil", .missingArtifactIdentity) { snapshot in
            snapshot.binaries[0].artifactIdentity = nil
        }
        try await assertRefusal("layout-nil", .missingSegmentLayout) { snapshot in
            snapshot.binaries[0].preferredSegmentLayout = nil
        }
        try await assertRefusal("fingerprint-nil", .missingAnalysisFingerprint) { snapshot in
            snapshot.analysisBySlot[.primary]?.analysisInputFingerprint = nil
        }
    }

    // MARK: - DR11 / DR12: full authoring fixtures

    func testFullAddressOverrideSurvivesCaptureReuse() async throws {
        // The whole value is built before the single observed map write.
        var signature = FunctionSignatureOverride()
        signature.returnType = "int"
        signature.parameterList = .authoritative([])
        signature.variadicState = .fixed
        signature.noReturnState = .returns
        signature.quarantinedLegacyArgs = []
        let cave = AppendedExecutableCaveAuthoring(ownerBinaryID: binaryID, functionID: functionID,
            selectedSliceSHA256: String(repeating: "a", count: 64), branchSourceAddress: 0x1000,
            codeBytes: Data(BytePatch.arm64NOP.bytes))
        var override = AddressOverride(
            customName: "renamed_entry", customComment: "authored comment", tag: "parser",
            colorTag: .red, isData: true, signature: signature,
            appliedTypeName: "NativeValidationRecord",
            switchHint: SwitchHintOverride(tableBase: 0x1000, entryCount: 1, entryStride: 4,
                                           isRelativeToBase: true),
            operandFormat: .hex, markAsProcedure: true,
            dataShape: DataShapeOverride(kind: .array, elementType: "int", elementCount: 1,
                                         alignment: 4, isNullTerminated: true, stringLength: 0,
                                         elementDisplayFormat: .hex),
            isUndefined: true, patch: BytePatch.arm64NOP, appendedExecutableCave: cave,
            registerNames: ["x19": "count"],
            stackLocals: ["value": StackLocalOverride(name: "value", typeName: "int")],
            localLabel: "loc_retry")
        // Session-only authority is assigned AFTER the signature; a later differing signature clears it.
        override.ownReturnAuthorityFile = "/shape-only/source.c"
        let expected = override
        let key = entryKey

        let edited = try await assertAuthoringSurvival("full-address-override") {
            $0.addressOverrides[key] = expected
        }
        let stored = try XCTUnwrap(edited.addressOverrides[key])
        XCTAssertEqual(stored, expected)
        XCTAssertEqual(stored.customName, "renamed_entry")
        XCTAssertEqual(stored.customComment, "authored comment")
        XCTAssertEqual(stored.tag, "parser")
        XCTAssertEqual(stored.colorTag, .red)
        XCTAssertTrue(stored.isData)
        XCTAssertEqual(stored.signature, signature)
        XCTAssertEqual(stored.ownReturnAuthorityFile, "/shape-only/source.c")
        XCTAssertEqual(stored.appliedTypeName, "NativeValidationRecord")
        XCTAssertEqual(stored.switchHint?.tableBase, 0x1000)
        XCTAssertEqual(stored.operandFormat, .hex)
        XCTAssertTrue(stored.markAsProcedure)
        XCTAssertEqual(stored.dataShape?.kind, .array)
        XCTAssertTrue(stored.isUndefined)
        XCTAssertEqual(stored.patch, BytePatch.arm64NOP)
        XCTAssertEqual(stored.patch?.bytes, [0x1f, 0x20, 0x03, 0xd5])
        XCTAssertEqual(stored.appendedExecutableCave, cave)
        XCTAssertEqual(stored.registerNames, ["x19": "count"])
        XCTAssertEqual(stored.stackLocals, ["value": StackLocalOverride(name: "value", typeName: "int")])
        XCTAssertEqual(stored.localLabel, "loc_retry")
    }

    func testFullTypeDefinitionSurvivesCaptureReuse() async throws {
        // Direct field settings after init avoid relying on constructor normalizers.
        var rules = AggregateLayoutRules()
        rules.isPacked = true
        rules.packAlignment = 4
        rules.minimumAlignment = 4
        let leaf = FieldDef(name: "value", type: "int")
        var field = FieldDef(name: "value", type: "int", declaratorSemanticsV1: .ordinary,
            bitWidth: 1, bitOffset: 0, isPacked: true, layoutIsUnknown: true, isAtomic: true,
            minimumAlignmentType: "int", inlineAggregateKind: .struct, inlineFields: [leaf],
            inlineAggregateLayoutRules: rules, promotesInlineFields: true, byteOffset: 0,
            layoutSource: .dwarf)
        field.minimumAlignment = 4
        let provenance = TypeInferenceProvenance(source: "usage-candidate-v1", candidateID: "value",
            root: "param:x0", functionStart: 0x1000, observationCount: 1, fieldCount: 1,
            conflictCount: 0, extentLowerBound: 4, incompleteness: ["budget"])
        var definition = TypeDefinition(id: functionID, kind: .struct, name: "NativeValidationRecord",
            fields: [field], vectorByteSize: 4, enumValuesIncomplete: true,
            inferenceProvenance: provenance)
        definition.layoutRules = rules
        let expected = definition

        let edited = try await assertAuthoringSurvival("full-type-definition") {
            $0.typeDefinitions = [expected]
        }
        XCTAssertEqual(edited.typeDefinitions, [expected])
        let stored = try XCTUnwrap(edited.typeDefinitions.first)
        XCTAssertEqual(stored.id, functionID)
        XCTAssertEqual(stored.kind, .struct)
        XCTAssertEqual(stored.name, "NativeValidationRecord")
        XCTAssertEqual(stored.layoutRules, rules)
        XCTAssertEqual(stored.vectorByteSize, 4)
        XCTAssertEqual(stored.enumValuesIncomplete, true)
        XCTAssertEqual(stored.inferenceProvenance, provenance)
        let storedField = try XCTUnwrap(stored.fields.first)
        XCTAssertEqual(storedField, field)
        XCTAssertEqual(storedField.declaratorSemanticsV1, .ordinary)
        XCTAssertNil(storedField.functionPointerSignatureV1)
        XCTAssertEqual(storedField.minimumAlignment, 4)
        XCTAssertEqual(storedField.inlineFields, [leaf])
        XCTAssertEqual(storedField.layoutSource, .dwarf)
        XCTAssertTrue(storedField.promotesInlineFields)
    }

    // MARK: - Shared oracles

    private func makeStore(_ work: FollowOnWork) -> NativeDecompilerValidatedImageStore {
        NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { work.enter() }))
    }

    private func assertSameBucket(_ actual: ImageAnalysis, _ expected: ImageAnalysis) {
        XCTAssertEqual(actual.functions, expected.functions)
        XCTAssertEqual(actual.imageBytes, expected.imageBytes)
        XCTAssertEqual(actual.analysisInputFingerprint, expected.analysisInputFingerprint)
    }

    /// The typed refusal of one capture; any other error is rethrown and fails the test.
    private func refusal(_ capture: () async throws -> NativeDecompilerSnapshotBuilder.ValidatedImage)
        async throws -> NativeDecompilerSnapshotProjectionError? {
        do {
            _ = try await capture()
            return nil
        } catch let error as NativeDecompilerSnapshotProjectionError {
            return error
        }
    }

    private func assertRefusal(_ id: String, _ expected: NativeDecompilerSnapshotProjectionError,
                               edit: (inout WorkspaceSnapshot) -> Void) async throws {
        let original = try makeFixture()
        let untouched = original
        let native = original.nativeImageValidationGenerationID
        let work = FollowOnWork()
        let store = makeStore(work)
        let token = try XCTUnwrap(NativeDecompilerAdmissionFence().advance())
        let registryID = UUID()
        let owner = UUID()
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: original, imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(work.attempts, 1, id)
        var edited = original
        edit(&edited)
        // FIRST assertion after the single indicated write. No refresh before or after.
        XCTAssertNotEqual(edited.nativeImageValidationGenerationID, native, id)
        XCTAssertEqual(untouched.nativeImageValidationGenerationID, native, id)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native, id)
        let current = edited
        let reusedError = try await refusal { try await store.captureForScripting(
            registryID: registryID, owner: owner, snapshot: current,
            imageSlot: .primary, admissionToken: token) }
        XCTAssertEqual(reusedError, expected, id)
        XCTAssertEqual(work.attempts, 2, id)
        let completed = await store.validationCount()
        XCTAssertEqual(completed, 1, id)
        let freshWork = FollowOnWork()
        let freshStore = makeStore(freshWork)
        let freshError = try await refusal { try await freshStore.captureForScripting(
            registryID: registryID, owner: owner, snapshot: current,
            imageSlot: .primary, admissionToken: token) }
        XCTAssertEqual(freshError, expected, id)
        XCTAssertEqual(freshWork.attempts, 1, id)
        let freshCompleted = await freshStore.validationCount()
        XCTAssertEqual(freshCompleted, 0, id)
    }

    /// One authoring write keeps the native token and renews the public generation, the retained
    /// capture is reused with one validation, and reuse equals a fresh capture of the same edited
    /// snapshot (equal projection, or the same exact typed refusal).
    private func assertAuthoringSurvival(_ id: String,
                                         edit: (inout WorkspaceSnapshot) -> Void) async throws -> WorkspaceSnapshot {
        let original = try makeFixture()
        let native = original.nativeImageValidationGenerationID
        let publicID = original.analysisGenerationID
        let work = FollowOnWork()
        let store = makeStore(work)
        let token = try XCTUnwrap(NativeDecompilerAdmissionFence().advance())
        let registryID = UUID()
        let owner = UUID()
        _ = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: original, imageSlot: .primary, admissionToken: token)
        var edited = original
        edit(&edited)
        XCTAssertEqual(edited.nativeImageValidationGenerationID, native, id)
        XCTAssertNotEqual(edited.analysisGenerationID, publicID, id)
        XCTAssertEqual(original.nativeImageValidationGenerationID, native, id)
        XCTAssertEqual(original.analysisGenerationID, publicID, id)
        XCTAssertEqual(edited.binaries, original.binaries, id)
        XCTAssertEqual(edited.imageBytes, original.imageBytes, id)
        XCTAssertEqual(edited.analysisInputFingerprint, original.analysisInputFingerprint, id)
        let reused = try await store.captureForScripting(registryID: registryID, owner: owner,
            snapshot: edited, imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(work.attempts, 1, id)
        let completed = await store.validationCount()
        XCTAssertEqual(completed, 1, id)
        let retained = await store.captureCount()
        XCTAssertEqual(retained, 1, id)
        let freshWork = FollowOnWork()
        let freshStore = makeStore(freshWork)
        let fresh = try await freshStore.captureForScripting(registryID: registryID, owner: owner,
            snapshot: edited, imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(freshWork.attempts, 1, id)
        let freshCompleted = await freshStore.validationCount()
        XCTAssertEqual(freshCompleted, 1, id)
        try assertImageAndProjectionEqual(reused, fresh, snapshot: edited, id: id)
        return edited
    }

    private func projectionOutcome(_ image: NativeDecompilerSnapshotBuilder.ValidatedImage,
                                   snapshot: WorkspaceSnapshot)
        throws -> Result<NativeDecompilerSnapshotProjection, NativeDecompilerSnapshotProjectionError> {
        do {
            return .success(try NativeDecompilerSnapshotBuilder.build(from: snapshot, validatedImage: image,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets))
        } catch let error as NativeDecompilerSnapshotProjectionError { return .failure(error) }
    }

    private func assertImageAndProjectionEqual(_ reused: NativeDecompilerSnapshotBuilder.ValidatedImage,
                                              _ fresh: NativeDecompilerSnapshotBuilder.ValidatedImage,
                                              snapshot: WorkspaceSnapshot, id: String) throws {
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

    private func makeFixture(byteCount: Int = 128) throws -> WorkspaceSnapshot {
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
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }
}

// Each store has its own counter; the observer hook fires before every validation guard.
private final class FollowOnWork: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = 0
    var attempts: Int { lock.withLock { stored } }
    func enter() { lock.withLock { stored += 1 } }
}
#endif
