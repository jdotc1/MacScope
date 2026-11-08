import Foundation
import XCTest
@testable import MacScope

/// Fresh source definitions only; real retained models, no parser or test execution.
@MainActor
final class ExactProtocolReadTests: XCTestCase {
    private let ownerID = UUID()
    private let secondary = ImageSlot(rawValue: 1)
    private func record(_ name: String = "P", _ address: UInt64 = 0x8000) -> ObjCProtocol {
        .init(name: name, address: address, adoptedProtocols: [], requiredMethods: [], optionalMethods: [], properties: [])
    }
    private func snapshot(_ records: [ObjCProtocol], slot: ImageSlot = .primary) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis(); analysis.objcProtocols = records
        return .init(binaries: [.init(id: ownerID, name: "protocols", path: "/ignored/protocols",
            kind: "Mach-O", architecture: "arm64", slot: slot)], analysisBySlot: [slot: analysis])
    }
    private func selector(_ key: TypeAtlasEntryID.Key = .address(0x8000), slot: ImageSlot = .primary,
                          kind: TypeAtlasKind = .objcProtocol) -> ExactProtocolReadSelector {
        .init(owner: .init(slot: slot, binaryID: ownerID, architecture: "arm64", sliceIndex: nil,
            ownerGeneration: 0), entryID: .init(slot: slot, kind: kind, key: key))
    }
    private func read(_ records: [ObjCProtocol], key: TypeAtlasEntryID.Key = .address(0x8000),
                      limits: ExactProtocolReadLimits = .init()) throws -> ScriptValue {
        try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(key), snapshot: snapshot(records), limits: limits)
    }
    func testSecondarySlotDoesNotLeakPrimarySameAddress() throws {
        var snap = snapshot([record("Secondary")], slot: secondary)
        snap.binaries.insert(.init(id: UUID(), name: "primary", path: "/ignored/primary", kind: "Mach-O",
            architecture: "arm64", slot: .primary), at: 0)
        var primary = ImageAnalysis(); primary.objcProtocols = [record("Primary")]
        snap.replaceAnalysis(primary, in: .primary)
        let value = try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(slot: secondary), snapshot: snap)
        XCTAssertEqual(value["imageSlot"], .int(1))
        XCTAssertEqual(value["imageOwner"], .string(ownerID.uuidString))
        XCTAssertEqual(value["protocol"]?["name"], .string("Secondary"))
        XCTAssertFalse(try XCTUnwrap(value["rendered"]?.stringValue).contains("Primary"))
    }
    func testExactAddressNameAndRequestedSelectorRetained() throws {
        let records = [record("P"), record("Other", 0x9000)]
        for key in [TypeAtlasEntryID.Key.address(0x8000), .name("P")] {
            let value = try read(records, key: key)
            XCTAssertEqual(value["status"], .string("found"))
            XCTAssertEqual(value["protocol"]?["address"], .hex(0x8000))
            XCTAssertEqual(value["selector"]?["kind"], .string("objcProtocol"))
            XCTAssertFalse(try XCTUnwrap(value["rendered"]?.stringValue).contains("Other"))
        }
        XCTAssertEqual(try read(records, key: .name("p"))["status"], .string("absentInCurrentRecoveredRecords"))
        XCTAssertEqual(try read(records, key: .name(" P"))["status"], .string("absentInCurrentRecoveredRecords"))
    }
    func testEmptyCapturedArrayIsAbsenceButMissingAnalysisRefuses() throws {
        let value = try read([])
        XCTAssertEqual(value["status"], .string("absentInCurrentRecoveredRecords"))
        XCTAssertEqual(value["rendered"], .null)
        XCTAssertTrue(try XCTUnwrap(value["scope"]?.stringValue).contains("absence is not completeness"))
        var snap = snapshot([]); snap.analysisBySlot = [:]
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snap)) {
            XCTAssertEqual($0 as? ExactProtocolReadFailure, .analysisUnavailable)
        }
    }
    func testIdenticalDuplicatesRemainMultipleInsteadOfRendererDeduplication() throws {
        let value = try read([record(), record()])
        XCTAssertEqual(value["status"], .string("multiple"))
        XCTAssertEqual(value["matches"]?.arrayValue?.count, 2)
        XCTAssertEqual(value["matches"]?.arrayValue?.last?["rawIndex"], .int(1))
        XCTAssertEqual(value["protocol"], .null)
        XCTAssertEqual(value["rendered"], .null)
    }
    func testAddressConflictAndNameConflictCannotBeFilteredAway() throws {
        for (records, key) in [([record(), record("Conflict")], TypeAtlasEntryID.Key.name("P")),
                               ([record(), record("P", 0x9000)], .address(0x8000))] {
            let value = try read(records, key: key)
            XCTAssertEqual(value["status"], .string("multiple"))
            XCTAssertEqual(value["matches"]?.arrayValue?.count, 2)
            XCTAssertEqual(value["rendered"], .null)
        }
        var conflicting = record(); conflicting.requiredMethods = [.init(selector: "x", typeEncoding: nil, isClassMethod: true)]
        XCTAssertEqual(try read([record(), conflicting])["status"], .string("multiple"))
    }
    func testCanonicalEquivalenceDoesNotMergeRetainedUTF8() throws {
        let composed = "\u{e9}", decomposed = "e\u{301}"
        let records = [record(composed), record(decomposed, 0x9000)]
        for (name, address) in [(composed, UInt64(0x8000)), (decomposed, UInt64(0x9000))] {
            let value = try read(records, key: .name(name))
            XCTAssertEqual(value["status"], .string("found"))
            XCTAssertEqual(value["protocol"]?["address"], .hex(address))
            XCTAssertTrue(try XCTUnwrap(value["protocol"]?["name"]?.stringValue).utf8.elementsEqual(name.utf8))
        }
    }
    func testCatalogDedupAndExternalAdoptionCannotSupplyAuthority() throws {
        var snap = snapshot([record(), record()])
        let row = TypeAtlasEntry(id: .init(slot: .primary, kind: .objcProtocol, key: .name("P")),
            kind: .objcProtocol, name: "P", superclass: nil, members: [], conformances: [], methods: [], users: [], evidence: .unknown)
        var analysis = try XCTUnwrap(snap.analysis(in: .primary))
        analysis.typeCatalog = .init(slot: .primary, entries: [row])
        snap.replaceAnalysis(analysis, in: .primary)
        XCTAssertEqual(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(.name("P")), snapshot: snap)["status"], .string("multiple"))
        analysis.objcProtocols = []
        analysis.objcClasses = [.init(name: "C", superclassName: nil, adoptedProtocols: ["P"],
            classMethods: [], instanceMethods: [], ivars: [], properties: [])]
        snap.replaceAnalysis(analysis, in: .primary)
        XCTAssertEqual(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(.name("P")), snapshot: snap)["status"], .string("absentInCurrentRecoveredRecords"))
    }
    func testRequiredOptionalClassInstancePropertyEncodingInheritedAndIMPFacts() throws {
        var p = record(); p.adoptedProtocols = ["External", "External"]
        p.requiredMethods = [.init(selector: "build", typeEncoding: "@16@0:8", isClassMethod: true, implementation: 0x1234)]
        p.optionalMethods = [.init(selector: "close", typeEncoding: "v16@0:8", isClassMethod: false)]
        p.properties = [.init(name: "title", attributes: "T@,R")]
        let value = try read([p]); let facts = try XCTUnwrap(value["protocol"])
        XCTAssertEqual(facts["requiredMethods"]?.arrayValue?.first?["retainedIMP"], .hex(0x1234))
        XCTAssertEqual(facts["requiredMethods"]?.arrayValue?.first?["typeEncoding"], .string("@16@0:8"))
        XCTAssertEqual(facts["optionalMethods"]?.arrayValue?.first?["isClassMethod"], .bool(false))
        XCTAssertEqual(facts["propertiesRequirementUnknown"]?.arrayValue?.first?["attributes"], .string("T@,R"))
        XCTAssertEqual(facts["inheritedUnresolvedNames"], .array([.string("External"), .string("External")]))
        let rendered = try XCTUnwrap(value["rendered"]?.stringValue)
        XCTAssertTrue(rendered.contains("@required\n+ (id)build;"))
        XCTAssertTrue(rendered.contains("@optional\n- (void)close;"))
        XCTAssertTrue(rendered.contains("requirement UNKNOWN"))
        XCTAssertTrue(rendered.contains("completeness unknown"))
        XCTAssertFalse(rendered.contains("1234"))
        XCTAssertTrue(try XCTUnwrap(value["renderingClaim"]?.stringValue).contains("not proof"))
    }
    func testBoundedMalformedRecordsPreserveFactsWithoutDeclarationClaim() throws {
        var p = record("Bad\n@end")
        p.requiredMethods = [.init(selector: "run", typeEncoding: "@\"Injected);\"", isClassMethod: false)]
        let value = try read([p])
        XCTAssertEqual(value["status"], .string("found")) // Raw unique record, NOT formatter success.
        XCTAssertEqual(value["protocol"]?["name"], .string(p.name))
        XCTAssertTrue(try XCTUnwrap(value["rendered"]?.stringValue).contains("Unsupported protocol name"))
        p.name = "Good"
        let diagnostic = try read([p])
        XCTAssertTrue(try XCTUnwrap(diagnostic["rendered"]?.stringValue).contains("display refused"))
        XCTAssertEqual(diagnostic["protocol"]?["requiredMethods"]?.arrayValue?.first?["typeEncoding"], .string("@\"Injected);\""))
    }
    func testUnsupportedOversizedInvalidAndMismatchedSelectorsRefuse() {
        for key in [TypeAtlasEntryID.Key.name(""), .name("P\n"), .name(String(repeating: "x", count: 1_025))] {
            XCTAssertThrowsError(try read([], key: key))
        }
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(kind: .objcClass), snapshot: snapshot([])))
        let wrong = ExactProtocolReadSelector(owner: selector().owner,
            entryID: .init(slot: secondary, kind: .objcProtocol, key: .address(0x8000)))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: wrong, snapshot: snapshot([])))
    }
    func testOwnerMembershipDuplicateRowsAndAbsentSlotsRefuse() {
        var snap = snapshot([]); snap.binaries.append(snap.binaries[0])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snap))
        snap.binaries[1].slot = secondary
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snap))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(slot: secondary), snapshot: snapshot([])))
    }
    func testAllTightenableBudgetsRefuseAtomically() throws {
        var p = record(); p.adoptedProtocols = ["A", "B"]
        let cases: [(inout ExactProtocolReadLimits) -> Void] = [
            { $0.selectorUTF8Bytes = 1 }, { $0.imageRows = 1 }, { $0.rawRecords = 1 },
            { $0.members = 1 }, { $0.textUTF8Bytes = 1 }, { $0.capturedUTF8Bytes = 1 },
            { $0.rendererUTF8Bytes = 1 }, { $0.projectionNodes = 1 }, { $0.projectionDepth = 1 },
            { $0.projectionUTF8Bytes = 1 }, { $0.encodedBytes = 1 }
        ]
        var snap = snapshot([p, record("Other", 0x9000)])
        snap.binaries.append(.init(id: UUID(), name: "other", path: "/ignored/other", kind: "Mach-O", architecture: "arm64", slot: secondary))
        for tighten in cases {
            var limits = ExactProtocolReadLimits(); tighten(&limits)
            XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(.name("P")), snapshot: snap, limits: limits))
        }
    }
    func testNonpositiveAndEnlargedBudgetsNeverEnlargeAuthority() {
        let changes: [(inout ExactProtocolReadLimits) -> Void] = [
            { $0.rawRecords = 0 }, { $0.rawRecords = 1_025 }, { $0.members = 4_097 },
            { $0.selectorUTF8Bytes = 1_025 }, { $0.imageRows = 257 }, { $0.textUTF8Bytes = 4_097 },
            { $0.capturedUTF8Bytes = 1_048_577 }, { $0.rendererUTF8Bytes = 2_097_153 },
            { $0.projectionNodes = 16_385 }, { $0.projectionDepth = 33 },
            { $0.projectionUTF8Bytes = 262_145 }, { $0.encodedBytes = 1_048_577 },
            { $0.duration = .zero }, { $0.duration = .seconds(11) }
        ]
        for change in changes {
            var limits = ExactProtocolReadLimits(); change(&limits)
            XCTAssertThrowsError(try read([], limits: limits))
        }
    }
    func testOversizedRawTextEncodingMembersAndAggregateNeverBecomeAbsence() {
        var text = record(String(repeating: "x", count: 4_097))
        XCTAssertThrowsError(try read([text], key: .address(0x9999)))
        text = record(); text.requiredMethods = [.init(selector: "x", typeEncoding: String(repeating: "x", count: 4_097), isClassMethod: false)]
        XCTAssertThrowsError(try read([text]))
        text = record(); text.properties = [.init(name: "x", attributes: String(repeating: "x", count: 4_097))]
        XCTAssertThrowsError(try read([text]))
        text = record(); text.adoptedProtocols = Array(repeating: "External", count: 4_097)
        XCTAssertThrowsError(try read([text]))
        text = record(); text.properties = Array(repeating: .init(name: "x", attributes: "T@"), count: 4_097)
        XCTAssertThrowsError(try read([text]))
        text.properties = Array(repeating: .init(name: String(repeating: "x", count: 4_096), attributes: "T@"), count: 257)
        XCTAssertThrowsError(try read([text]))
        XCTAssertThrowsError(try read(Array(repeating: record(), count: 1_025)))
    }
    func testRendererExpansionAndJSONEscapingAreAdmittedBeforeFormatting() {
        var p = record(); p.properties = Array(repeating: .init(name: String(repeating: "\u{7f}", count: 160), attributes: ""), count: 4_096)
        XCTAssertThrowsError(try read([p]))
        var limits = ExactProtocolReadLimits(); limits.encodedBytes = 10_000
        XCTAssertThrowsError(try read([record()], limits: limits))
    }
    func testRepeatedMaximumAddressTextTightProjectionCapRefusesAtomically() {
        // Regression definition: v1 reserved only captured names, omitting 1,024 generated
        // match address strings. Each row alone carries 18 address bytes plus its one-byte name.
        let records = Array(repeating: record("P", UInt64.max), count: 1_024)
        var limits = ExactProtocolReadLimits(); limits.projectionUTF8Bytes = 12_000
        var delivered: ScriptValue?
        do {
            delivered = try read(records, key: .address(UInt64.max), limits: limits)
            XCTFail("tight complete-projection text cap must refuse, not return a prefix")
        } catch {
            XCTAssertEqual(error as? ExactProtocolReadFailure, .limitExceeded)
        }
        XCTAssertNil(delivered)
    }
    func testRepeatedMaximumAddressTextSufficientCapRetainsEveryAmbiguousRow() throws {
        let records = Array(repeating: record("P", UInt64.max), count: 1_024)
        var limits = ExactProtocolReadLimits(); limits.projectionUTF8Bytes = 65_536
        let value = try read(records, key: .address(UInt64.max), limits: limits)
        XCTAssertEqual(value["status"], .string("multiple"))
        let matches = try XCTUnwrap(value["matches"]?.arrayValue)
        XCTAssertEqual(matches.count, 1_024)
        XCTAssertEqual(matches.first?["rawIndex"], .int(0))
        XCTAssertEqual(matches.last?["rawIndex"], .int(1_023))
        for row in matches {
            XCTAssertEqual(row["name"], .string("P"))
            XCTAssertEqual(row["address"], .hex(UInt64.max))
        }
        XCTAssertEqual(value["protocol"], .null)
        XCTAssertEqual(value["rendered"], .null)
        // Test-only traversal accounts for every projected key/string occurrence, not a
        // deduplicated set or raw-input sum. This is a definition, not executed evidence.
        func textBytes(_ value: ScriptValue) -> Int {
            switch value {
            case .string(let text): return text.utf8.count
            case .array(let children): return children.reduce(0) { $0 + textBytes($1) }
            case .object(let fields):
                return fields.reduce(0) { $0 + $1.key.utf8.count + textBytes($1.value) }
            default: return 0
            }
        }
        XCTAssertGreaterThan(textBytes(value), 12_000)
        XCTAssertLessThanOrEqual(textBytes(value), limits.projectionUTF8Bytes)
        XCTAssertLessThanOrEqual(try value.jsonData().count, limits.encodedBytes)
    }
    func testSufficientProjectionTextDoesNotBypassIndependentEncodedCap() {
        let records = Array(repeating: record("P", UInt64.max), count: 1_024)
        var limits = ExactProtocolReadLimits()
        limits.projectionUTF8Bytes = 65_536
        limits.encodedBytes = 1
        var delivered: ScriptValue?
        do {
            delivered = try read(records, key: .address(UInt64.max), limits: limits)
            XCTFail("independent encoded-wrapper ceiling must still refuse atomically")
        } catch {
            XCTAssertEqual(error as? ExactProtocolReadFailure, .limitExceeded)
        }
        XCTAssertNil(delivered)
    }
    func testOriginalDeadlineAndTightDurationUseClockWithoutSleep() {
        let start = ContinuousClock.now; var calls = 0
        var limits = ExactProtocolReadLimits(); limits.duration = .milliseconds(1)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snapshot([]), limits: limits, now: {
            calls += 1; return calls == 1 ? start : start.advanced(by: .milliseconds(1))
        })) { XCTAssertEqual($0 as? ExactProtocolReadFailure, .deadlineExceeded) }
    }
    func testCancellationCheckpointBeforeAndDuringRawScan() {
        for stop in [1, 6, 12] {
            var checkpoints = 0
            XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snapshot([record(), record("Other", 0x9000)]), checkpoint: {
                checkpoints += 1; if checkpoints == stop { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
            XCTAssertEqual(checkpoints, stop)
        }
    }
    func testAlreadyCancelledTaskCannotProject() async throws {
        let snap = snapshot([]), requested = selector()
        try await Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            XCTAssertThrowsError(try WorkspaceScriptingAPI.exactProtocolRead(selector: requested, snapshot: snap)) {
                XCTAssertTrue($0 is CancellationError)
            }
        }.value
    }
    func testExistingClassAndCategoryExportTextRemainsUnchanged() throws {
        var snap = snapshot([record()])
        var analysis = try XCTUnwrap(snap.analysis(in: .primary))
        analysis.objcClasses = [.init(name: "RetainedClass", superclassName: nil, adoptedProtocols: [],
            classMethods: [], instanceMethods: [], ivars: [], properties: [])]
        analysis.objcCategories = [.init(name: "RetainedCategory", className: "RetainedClass",
            classMethods: [], instanceMethods: [], adoptedProtocols: [], properties: [])]
        snap.replaceAnalysis(analysis, in: .primary)
        let expected = "@interface RetainedClass\n@end\n\n@interface RetainedClass (RetainedCategory)\n@end"
        XCTAssertEqual(ObjectiveCHeaderRenderer.render(classes: analysis.objcClasses, categories: analysis.objcCategories), expected)
        let before = DocumentExportService().renderObjectiveCHeader(snapshot: snap)
        _ = try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snap)
        XCTAssertEqual(DocumentExportService().renderObjectiveCHeader(snapshot: snap), before)
    }
    func testDefaultExportsSharedListingAndFrozenOperationSurfaceUnchanged() throws {
        let snap = snapshot([record()])
        let args = ScriptValue.object(["image": .int(0), "limit": .int(5_000)])
        let before = try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types", arguments: args, snapshot: snap)
        _ = try WorkspaceScriptingAPI.exactProtocolRead(selector: selector(), snapshot: snap)
        XCTAssertEqual(try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types", arguments: args, snapshot: snap), before)
        XCTAssertEqual(DocumentExportService().renderObjectiveCHeader(snapshot: snap), "// No Objective-C classes were recovered from this binary.\n")
        XCTAssertNil(TypedReadRegistry().descriptor(for: .init(rawValue: "types.protocol.read")))
        XCTAssertEqual(TypedReadRegistry.ExternalOperation.allCases.map(\.rawValue), ["workspace.summary", "application.graph.summary", "function.review"])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: .init(owner: selector().owner, entryID: selector().entryID), snapshot: snap))
    }
}
