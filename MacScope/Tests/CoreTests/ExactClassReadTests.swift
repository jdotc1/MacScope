import Foundation
import XCTest
@testable import MacScope

/// These exercise the real snapshot/catalog/projector, not a stand-in.
@MainActor
final class ExactClassReadTests: XCTestCase {
    private let binaryID = UUID()
    private func entry(_ address: UInt64 = 0x8000, kind: TypeAtlasKind = .objcClass,
                       name: String = "Same") -> TypeAtlasEntry {
        .init(id: .init(slot: .primary, kind: kind, key: .address(address)), kind: kind,
              name: name, superclass: nil, members: [], conformances: [], methods: [],
              users: [], evidence: .descriptor)
    }
    private func snapshot(_ entries: [TypeAtlasEntry]) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        return .init(binaries: [.init(id: binaryID, name: "types", path: "/ignored/types",
            kind: "Mach-O", architecture: "arm64")], analysisBySlot: [.primary: analysis])
    }
    private func selector(_ address: UInt64 = 0x8000, kind: TypeAtlasKind = .objcClass) -> ExactClassReadSelector {
        .init(owner: .init(slot: .primary, binaryID: binaryID, architecture: "arm64", sliceIndex: nil,
                           ownerGeneration: 0), entryID: .init(slot: .primary, kind: kind, key: .address(address)))
    }
    func testExactObjCAndSwiftRowsPreserveSharedProjection() throws {
        for kind in [TypeAtlasKind.objcClass, .swiftClass] {
            var e = entry(kind: kind)
            e.members = [.init(name: "field", type: nil, offset: nil, evidence: .unknown)]
            e.methods = [.init(name: "retained", implementation: nil)]
            if kind == .swiftClass {
                e.qualifiedName = "Module.Outer.Same"
                e.swiftSuperclass = "$s6Module4BaseC"
                e.isGeneric = true; e.isPrivateOrLocal = false; e.isImportedCType = false
                e.swiftMethodTableResolved = false
                e.methods[0].swiftMetadata = .init(source: .vtable, index: UInt64.max,
                    descriptorAddress: 0x8010, implementation: nil, flags: nil)
                e.swiftConformanceMethods = [.init(protocolName: "P", descriptorAddress: 0x8020, methods: nil)]
            } else {
                e.instanceSize = 32
                e.methods[0].isClassMethod = true
                e.methods[0].selectorUsers = [0x8100]
            }
            let result = try WorkspaceScriptingAPI.exactClassRead(selector: selector(kind: kind), snapshot: snapshot([e]))
            XCTAssertEqual(result["status"], .string("found"))
            XCTAssertEqual(result["class"], WorkspaceScriptingAPI.typeAtlasEntryValue(e))
            XCTAssertEqual(result["imageOwner"], .string(binaryID.uuidString))
            XCTAssertEqual(result["class"]?["members"]?.arrayValue?.first?["offset"], .null)
            if kind == .swiftClass {
                XCTAssertEqual(result["class"]?["qualifiedName"], .string("Module.Outer.Same"))
                XCTAssertEqual(result["class"]?["swiftSuperclass"], .string("$s6Module4BaseC"))
                XCTAssertEqual(result["class"]?["isGeneric"], .bool(true))
                XCTAssertEqual(result["class"]?["isPrivateOrLocal"], .bool(false))
                XCTAssertEqual(result["class"]?["isImportedCType"], .bool(false))
                XCTAssertEqual(result["class"]?["methods"]?.arrayValue?.first?["swiftMetadata"]?["index"],
                    .string(String(UInt64.max)))
            }
        }
    }
    func testAddressIdentityNotNameSelectsOneOfEqualNames() throws {
        let a = entry(), b = entry(0x9000)
        let result = try WorkspaceScriptingAPI.exactClassRead(selector: selector(0x9000), snapshot: snapshot([a, b]))
        XCTAssertEqual(result["class"], WorkspaceScriptingAPI.typeAtlasEntryValue(b))
    }
    func testEqualAddressInAnotherImageDoesNotSelectIt() throws {
        var snap = snapshot([])
        let other = ImageSlot(rawValue: 1)
        snap.binaries.append(.init(id: UUID(), name: "other", path: "/ignored/other", kind: "Mach-O",
                                   architecture: "arm64", slot: other))
        var otherAnalysis = ImageAnalysis()
        otherAnalysis.typeCatalog = .init(slot: other, entries: [entry()])
        snap.replaceAnalysis(otherAnalysis, in: other)
        let result = try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snap)
        XCTAssertEqual(result["status"], .string("notFoundInCurrentCatalog"))
        XCTAssertEqual(result["class"], .null)
    }
    func testDuplicateExactRowsRefuseEvenIfIdentical() {
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([entry(), entry()]))) {
            XCTAssertEqual($0 as? ExactClassReadFailure, .ambiguousEntry)
        }
    }
    func testMalformedCachedKindIdentityCannotHideDuplicate() {
        var malformed = entry()
        malformed.kind = .swiftClass // Same actual ID, conflicting row kind must not be filtered away.
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(),
            snapshot: snapshot([entry(), malformed])))
    }
    func testWrongKindAndWrongOwnerRefuse() {
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(kind: .swiftStruct), snapshot: snapshot([])))
        let wrong = ExactClassReadSelector(owner: .init(slot: .primary, binaryID: UUID(), architecture: "arm64",
            sliceIndex: nil, ownerGeneration: 0), entryID: selector().entryID)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: wrong, snapshot: snapshot([entry()])))
    }
    func testDuplicateImageSlotAndDuplicateOwnerRefuse() {
        var snap = snapshot([entry()])
        snap.binaries.append(snap.binaries[0])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snap))
        snap.binaries[1].slot = .init(rawValue: 1)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snap))
    }
    func testNoAnalysisIsUnavailableNotAbsent() {
        var snap = snapshot([])
        snap.analysisBySlot = [:]
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snap)) {
            XCTAssertEqual($0 as? ExactClassReadFailure, .analysisUnavailable)
        }
    }
    func testSelectorStringAndUnsupportedKindAreBounded() throws {
        let requested = ExactClassReadSelector(owner: selector().owner,
            entryID: .init(slot: .primary, kind: .objcClass, key: .name(String(repeating: "x", count: 1_025))))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: requested, snapshot: snapshot([])))
        var named = entry(); named.id.key = .name("Same")
        let exactName = ExactClassReadSelector(owner: selector().owner, entryID: named.id)
        XCTAssertEqual(try WorkspaceScriptingAPI.exactClassRead(selector: exactName,
            snapshot: snapshot([named]))["class"], WorkspaceScriptingAPI.typeAtlasEntryValue(named))
        XCTAssertEqual(try WorkspaceScriptingAPI.exactClassRead(selector: exactName,
            snapshot: snapshot([entry()]))["status"], .string("notFoundInCurrentCatalog"))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(kind: .objcProtocol),
            snapshot: snapshot([])))
    }
    func testCatalogOverCapCannotBecomeNotFound() {
        let rows = (0..<4_097).map { entry(UInt64($0)) }
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(UInt64.max), snapshot: snapshot(rows)))
    }
    func testTightSearchBoundCannotTruncateToAbsence() {
        var limits = ExactClassReadLimits(); limits.searchRows = 1
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(0xA000),
            snapshot: snapshot([entry(), entry(0x9000)]), limits: limits))
    }
    func testNestedPreflightRefusesBeforeProjection() {
        var e = entry()
        e.methods = (0..<4_097).map { .init(name: "m\($0)", implementation: nil) }
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([e])))
    }
    func testCompleteWrapperEncodedCapAndProjectionCapRefuse() {
        var limits = ExactClassReadLimits(); limits.encodedBytes = 1
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([entry()]), limits: limits))
        limits = .init(); limits.projectionNodes = 1
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([entry()]), limits: limits))
        limits = .init(); limits.projectionUTF8Bytes = 1
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([]), limits: limits))
    }
    func testDeadlineStartsBeforeCatalogProjection() {
        let instant = ContinuousClock.now
        var reads = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([entry()]), now: {
            reads += 1; return reads == 1 ? instant : instant.advanced(by: .seconds(11))
        })) { XCTAssertEqual($0 as? ExactClassReadFailure, .deadlineExceeded) }
    }
    func testCheckpointCancellationStopsBeforeResult() {
        XCTAssertThrowsError(try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snapshot([entry()]),
            checkpoint: { throw CancellationError() })) { XCTAssertTrue($0 is CancellationError) }
    }
    func testSharedListingUnchangedAndNoFrozenOperationAdded() throws {
        let snap = snapshot([entry()])
        let args = ScriptValue.object(["image": .int(0), "kind": .string("objcClass"), "limit": .int(5_000)])
        let before = try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types", arguments: args, snapshot: snap)
        _ = try WorkspaceScriptingAPI.exactClassRead(selector: selector(), snapshot: snap)
        XCTAssertEqual(try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types", arguments: args, snapshot: snap), before)
        XCTAssertNil(TypedReadRegistry().descriptor(for: .init(rawValue: "types.class.read")))
    }
}
