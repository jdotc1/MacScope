import Foundation
import XCTest
@testable import MacScope

@MainActor
final class TypeAtlasRetainedFactsProjectionTests: XCTestCase {
    private func row(_ kind: TypeAtlasKind = .objcProtocol) -> TypeAtlasEntry {
        TypeAtlasEntry(id: .init(slot: .primary, kind: kind, key: .address(0x1000)),
            kind: kind, name: "Retained", superclass: nil, members: [], conformances: [],
            methods: [], users: [], evidence: .descriptor)
    }

    private func metadata(_ source: SwiftMetadataMethod.Source = .vtable, index: UInt64 = 0,
                          descriptor: UInt64 = 0x2000, flags: UInt32? = nil) -> SwiftMetadataMethod {
        .init(source: source, index: index, descriptorAddress: descriptor,
              implementation: 0x3000, flags: flags)
    }

    private func method(_ metadata: SwiftMetadataMethod) -> TypeAtlasMethod {
        .init(name: metadata.label, implementation: metadata.implementation,
              isClassMethod: metadata.isInstance == false, swiftMetadata: metadata)
    }

    private func snapshot(_ entries: [TypeAtlasEntry]) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        return snapshot(analysis: analysis)
    }

    private func snapshot(analysis: ImageAnalysis) -> WorkspaceSnapshot {
        WorkspaceSnapshot(binaries: [BinaryImage(id: UUID(), name: "retained", path: "/retained",
            kind: "Mach-O", architecture: "arm64")], analysisBySlot: [.primary: analysis])
    }

    private func read(_ snapshot: WorkspaceSnapshot) throws -> ScriptValue {
        try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types", arguments: .object([:]),
                                                        snapshot: snapshot)
    }

    private func store(_ snapshot: WorkspaceSnapshot) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "retained-facts", snapshot: snapshot,
                       engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    func testProtocolRequirementFlagsPreserveUnknownFalseTrueAndLegacyFields() throws {
        var entry = row()
        entry.methods = [nil, false, true].map {
            TypeAtlasMethod(name: "same:", implementation: nil, isClassMethod: true,
                            selectorUsers: [0x55, 0x55], isOptionalRequirement: $0)
        }
        let value = WorkspaceScriptingAPI.typeAtlasEntryValue(entry)
        let methods = try XCTUnwrap(value["methods"]?.arrayValue)
        XCTAssertEqual(methods.map { $0["isOptionalRequirement"] }, [.null, .bool(false), .bool(true)])
        for method in methods {
            XCTAssertEqual(method["name"], .string("same:"))
            XCTAssertEqual(method["implementation"], .null)
            XCTAssertEqual(method["isClassMethod"], .bool(true))
            XCTAssertEqual(method["selectorUsers"], .array([.hex(0x55), .hex(0x55)]))
            XCTAssertNil(method["swiftMetadata"])
        }
    }

    func testProtocolPropertiesPreserveNilEmptyRawAttributesAndMultiplicity() {
        var entry = row()
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["declaredProperties"], .null)
        entry.declaredProperties = []
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["declaredProperties"], .array([]))
        let raw = "T@\"Name\",&,N,V_raw\n\t"
        entry.declaredProperties = [.init(name: "value", attributes: raw), .init(name: "value", attributes: raw)]
        let value = WorkspaceScriptingAPI.typeAtlasEntryValue(entry)
        XCTAssertEqual(value["declaredProperties"], .array(Array(repeating: .object([
            "name": .string("value"), "attributes": .string(raw)]), count: 2)))
        XCTAssertEqual(value["members"], .array([]), "Requirements must not become storage")
    }

    func testClassAndCategoryDoNotInventPropertyExtractionOrRequirementFlags() {
        for kind in [TypeAtlasKind.objcClass, .objcCategory] {
            var entry = row(kind)
            entry.methods = [.init(name: "method", implementation: nil)]
            let value = WorkspaceScriptingAPI.typeAtlasEntryValue(entry)
            XCTAssertNil(value["declaredProperties"])
            XCTAssertNil(value["methods"]?.arrayValue?.first?["isOptionalRequirement"])
            XCTAssertNil(value["swiftConformanceMethods"])
        }
    }

    func testSwiftRecordSourcesFlagsSharedCodeAndLargeIdentityAreLossless() throws {
        var entry = row(.swiftClass)
        entry.methods = [method(metadata(.vtable, index: .max, descriptor: .max)),
                         method(metadata(.override, index: 1, descriptor: 0x2004, flags: 0)),
                         method(metadata(.witness, index: 2, descriptor: 0x2008, flags: 0x10))]
        let methods = try XCTUnwrap(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["methods"]?.arrayValue)
        XCTAssertEqual(methods.map { $0["swiftMetadata"]?["source"] },
                       [.string("vtable"), .string("override"), .string("witness")])
        XCTAssertEqual(methods[0]["swiftMetadata"]?["index"], .string("18446744073709551615"))
        XCTAssertEqual(methods[0]["swiftMetadata"]?["descriptorAddress"], .hex(.max))
        XCTAssertEqual(methods.map { $0["swiftMetadata"]?["flags"] }, [.null, .int(0), .int(16)])
        XCTAssertEqual(methods.map { $0["swiftMetadata"]?["isInstance"] }, [.null, .bool(false), .bool(true)])
        XCTAssertEqual(methods.map { $0["implementation"] }, Array(repeating: .hex(0x3000), count: 3))
        XCTAssertEqual(methods[0]["name"], .string("vtable #18446744073709551615 (name unknown)"))
        XCTAssertEqual(methods.map { $0["isClassMethod"] }, [.bool(false), .bool(true), .bool(false)])
    }

    func testMetadataIntegerBoundaryAndMaximumFlagsStayExact() {
        var entry = row(.swiftClass)
        entry.methods = [method(metadata(index: UInt64(Int64.max), flags: .max)),
                         method(metadata(index: UInt64(Int64.max) + 1, flags: 0))]
        let methods = WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["methods"]?.arrayValue
        XCTAssertEqual(methods?[0]["swiftMetadata"]?["index"], .int(Int64.max))
        XCTAssertEqual(methods?[1]["swiftMetadata"]?["index"], .string("9223372036854775808"))
        XCTAssertEqual(methods?[0]["swiftMetadata"]?["flags"], .int(4_294_967_295))
    }

    func testMissingSwiftMetadataAndImplementationRemainNull() {
        var entry = row(.swiftStruct)
        var unknown = metadata()
        unknown.implementation = nil
        entry.methods = [.init(name: "retained", implementation: nil), method(unknown)]
        let methods = WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["methods"]?.arrayValue
        XCTAssertEqual(methods?[0]["swiftMetadata"], .null)
        XCTAssertEqual(methods?[1]["swiftMetadata"]?["implementation"], .null)
        XCTAssertEqual(methods?[1]["swiftMetadata"]?["flags"], .null)
    }

    func testConformanceNullEmptyDistinctDescriptorsAndDuplicateNamesStaySeparate() throws {
        var entry = row(.swiftClass)
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["swiftConformanceMethods"], .null)
        entry.swiftConformanceMethods = []
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["swiftConformanceMethods"], .array([]))
        entry.swiftConformanceMethods = [
            .init(protocolName: "P", descriptorAddress: nil, methods: nil),
            .init(protocolName: "P", descriptorAddress: 0x4000, methods: []),
            .init(protocolName: "P", descriptorAddress: 0x4010, methods: [method(metadata(.witness))]),
        ]
        let values = try XCTUnwrap(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["swiftConformanceMethods"]?.arrayValue)
        XCTAssertEqual(values.count, 3)
        XCTAssertEqual(values.map { $0["protocolName"] }, Array(repeating: .string("P"), count: 3))
        XCTAssertEqual(values.map { $0["descriptorAddress"] }, [.null, .hex(0x4000), .hex(0x4010)])
        XCTAssertEqual(values[0]["methods"], .null)
        XCTAssertEqual(values[1]["methods"], .array([]))
        XCTAssertEqual(values[2]["methods"]?.arrayValue?.first?["swiftMetadata"]?["source"], .string("witness"))
    }

    func testMethodTableResolutionDoesNotCollapseUnknownIntoFalseOrEmpty() {
        var entry = row(.swiftClass)
        for (retained, expected) in [(nil as Bool?, ScriptValue.null), (false, .bool(false)), (true, .bool(true))] {
            entry.swiftMethodTableResolved = retained
            XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["swiftMethodTableResolved"], expected)
        }
    }

    func testNonapplicableUserAndImportedRowsKeepExactLegacyShape() {
        for kind in [TypeAtlasKind.userType, .importedType] {
            var entry = row(kind)
            entry.id.key = .name("Legacy")
            entry.name = "Legacy"
            entry.evidence = kind == .userType ? .authored : .compilerImport
            let expected = ScriptValue.object([
                "id": .object(["slot": .int(0), "kind": .string(kind.rawValue), "name": .string("Legacy")]),
                "imageSlot": .int(0), "kind": .string(kind.rawValue), "name": .string("Legacy"),
                "superclass": .null, "members": .array([]), "conformances": .array([]),
                "methods": .array([]), "users": .array([]), "evidence": .string(entry.evidence.rawValue),
            ])
            XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(entry), expected)
        }
    }

    func testSyncSnapshotAndAttachedRepliesAgreeForRetainedProtocolFacts() async throws {
        var entry = row()
        entry.declaredProperties = [.init(name: "title", attributes: "T@,R")]
        entry.methods = [.init(name: "title", implementation: nil, isOptionalRequirement: false)]
        let store = store(snapshot([entry]))
        let expected = try WorkspaceScriptingAPI(store: store).execute("list-image-types", arguments: .object([:]))
        XCTAssertEqual(try read(store.snapshot), expected)
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let attached = try await executor.execute("list-image-types", .object([:]))
        XCTAssertEqual(attached, expected)
    }

    func testUncachedBuilderCarriesActualProtocolAndSwiftWitnessFacts() throws {
        var analysis = ImageAnalysis()
        analysis.objcProtocols = [.init(name: "P", address: 0x1000, adoptedProtocols: [],
            requiredMethods: [.init(selector: "required", typeEncoding: nil, isClassMethod: false)],
            optionalMethods: [.init(selector: "optional", typeEncoding: nil, isClassMethod: true)],
            properties: [.init(name: "title", attributes: "T@,R")])]
        analysis.swiftTypes = [.init(kind: .class, name: "C", descriptorAddress: 0x2000,
                                     methods: [metadata(.vtable)])]
        analysis.swiftConformances = [.init(typeName: "C", protocolName: "P", descriptorAddress: 0x4000,
                                           typeDescriptorAddress: 0x2000, methods: [metadata(.witness)])]
        let rows = try XCTUnwrap(read(snapshot(analysis: analysis))["types"]?.arrayValue)
        let proto = try XCTUnwrap(rows.first { $0["kind"] == .string("objcProtocol") })
        XCTAssertEqual(proto["methods"]?.arrayValue?.map { $0["isOptionalRequirement"] }, [.bool(false), .bool(true)])
        XCTAssertEqual(proto["declaredProperties"], .array([.object(["name": .string("title"), "attributes": .string("T@,R")])]))
        let swift = try XCTUnwrap(rows.first { $0["kind"] == .string("swiftClass") })
        XCTAssertEqual(swift["swiftMethodTableResolved"], .bool(true))
        XCTAssertEqual(swift["swiftConformanceMethods"]?.arrayValue?.first?["descriptorAddress"], .hex(0x4000))
        XCTAssertEqual(swift["swiftConformanceMethods"]?.arrayValue?.first?["methods"]?.arrayValue?.first?["swiftMetadata"]?["source"], .string("witness"))
    }

    func testEqualDescriptorAddressesStayQualifiedBySlotAndOwner() throws {
        var primary = row(.swiftClass), secondary = row(.swiftClass)
        primary.name = "Primary"
        secondary.name = "Secondary"
        let secondSlot = ImageSlot(rawValue: 1)
        secondary.id.slot = secondSlot
        var snap = snapshot([primary])
        var secondImage = BinaryImage(id: UUID(), name: "secondary", path: "/secondary", kind: "Mach-O", architecture: "arm64")
        secondImage.slot = secondSlot
        snap.binaries.append(secondImage)
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: secondSlot, entries: [secondary])
        snap.analysisBySlot[secondSlot] = analysis
        let first = try read(snap)
        let second = try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types",
            arguments: .object(["image": .int(1)]), snapshot: snap)
        XCTAssertNotEqual(first["imageOwner"], second["imageOwner"])
        XCTAssertEqual(second["imageSlot"], .int(1))
        XCTAssertEqual(second["types"]?.arrayValue?.first?["id"]?["slot"], .int(1))
        XCTAssertEqual(second["types"]?.arrayValue?.first?["id"]?["address"], .hex(0x1000))
        XCTAssertEqual(second["types"]?.arrayValue?.first?["name"], .string("Secondary"))
    }

    func testCachedPropertyTextRefusesBeforeRowPrefixMaterialization() {
        var entry = row()
        entry.declaredProperties = [.init(name: "p", attributes: String(repeating: "x", count: 2_049))]
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types",
            arguments: .object(["limit": .int(0)]), snapshot: snapshot([entry])))
    }

    func testUncachedProtocolPropertyTextRefusesBeforeCatalogConstruction() {
        var analysis = ImageAnalysis()
        analysis.objcProtocols = [.init(name: "P", address: 0x1000, adoptedProtocols: [], requiredMethods: [],
            optionalMethods: [], properties: [.init(name: "p", attributes: String(repeating: "x", count: 2_049))])]
        XCTAssertThrowsError(try read(snapshot(analysis: analysis)))
    }

    func testCachedMetadataFramingHasIndependentFiniteByteBudget() {
        var entry = row(.swiftClass)
        entry.methods = Array(repeating: method(metadata()), count: 900)
        // 1,801 nodes fit the old 4,096 cap. Newly exposed fixed metadata must still refuse.
        XCTAssertThrowsError(try read(snapshot([entry])))
    }

    func testUncachedMetadataFramingRefusesBeforeBuilderCopiesMethods() {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [.init(kind: .class, name: "C", descriptorAddress: 0x1000,
                                     methods: Array(repeating: metadata(), count: 900))]
        XCTAssertThrowsError(try read(snapshot(analysis: analysis)))
    }

    func testCachedConformanceNestedCountCannotHideBehindOneRow() {
        var entry = row(.swiftClass)
        entry.swiftConformanceMethods = [.init(protocolName: "P", descriptorAddress: nil,
            methods: Array(repeating: .init(name: "unknown", implementation: nil), count: 4_097))]
        XCTAssertThrowsError(try read(snapshot([entry])))
    }

    func testUncachedConformanceNestedCountCannotHideBehindOneType() {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [.init(kind: .struct, name: "S", descriptorAddress: 0x1000)]
        analysis.swiftConformances = [.init(typeName: "S", protocolName: "P", typeDescriptorAddress: 0x1000,
                                          methods: Array(repeating: metadata(.witness), count: 4_097))]
        XCTAssertThrowsError(try read(snapshot(analysis: analysis)))
    }

    func testPropertyAggregateBytesRefuseEvenWithEachStringWithinLimit() {
        var entry = row()
        entry.declaredProperties = Array(repeating: .init(name: "p", attributes: String(repeating: "x", count: 1_900)), count: 140)
        XCTAssertThrowsError(try read(snapshot([entry])))
    }

    func testNewNestedPreparationPropagatesCancellationWithoutResult() {
        var entry = row(.swiftClass)
        entry.methods = [method(metadata()), method(metadata(.override)), method(metadata(.witness))]
        var checkpoints = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types",
            arguments: .object([:]), snapshot: snapshot([entry]), checkpoint: {
                checkpoints += 1
                if checkpoints == 6 { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(checkpoints, 6)
    }

    func testRevokedAttachedNewFactsNeverPublishAfterPreparationEntry() async throws {
        var entry = row(.swiftClass)
        entry.methods = [method(metadata()), method(metadata(.override)), method(metadata(.witness))]
        let store = store(snapshot([entry]))
        let gate = RetainedFactsPreparationGate()
        let executor = MCPAttachExecutor(store: store, api: {
            WorkspaceScriptingAPI(store: $0, snapshotReadCheckpoint: { gate.park() })
        })
        executor.setConsent(.allowed)
        let read = Task { try await executor.execute("list-image-types", .object([:])) }
        defer { gate.release() }
        let entered = await gate.waitUntilEntered()
        XCTAssertTrue(entered)
        executor.setConsent(.revoked)
        gate.release()
        do { _ = try await read.value; XCTFail("Revoked structured facts were published") } catch { }
        XCTAssertFalse(gate.expired)
    }

    func testExistingMCPSerializedWrapperCapRejectsNewFactsWithoutTruncatingThem() async throws {
        var entry = row(.swiftClass)
        entry.methods = [method(metadata()), method(metadata(.override)), method(metadata(.witness))]
        let store = store(snapshot([entry]))
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 1_024, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: .max, maximumRememberedCancellations: 8))
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("list-image-types"), "arguments": .object([:])])])
        let response = await server.handleMessageAsync(try request.jsonData())
        let bytes = try XCTUnwrap(response)
        XCTAssertLessThanOrEqual(bytes.count, 512)
        let envelope = try ScriptValue.decode(bytes)
        XCTAssertEqual(envelope["error"]?["code"], .int(-32603))
        XCTAssertNil(envelope["result"])
    }
}

/// Entry/release are latched. Timeouts only bound a broken test; they do not establish ordering.
private final class RetainedFactsPreparationGate: @unchecked Sendable {
    private let lock = NSLock()
    private let entered = DispatchSemaphore(value: 0)
    private let resume = DispatchSemaphore(value: 0)
    private var count = 0
    private var released = false
    private var timedOut = false
    var expired: Bool { lock.withLock { timedOut } }
    func park() {
        let shouldPark = lock.withLock { count += 1; return count == 6 }
        guard shouldPark else { return }
        entered.signal()
        if resume.wait(timeout: .now() + 2) == .timedOut { lock.withLock { timedOut = true } }
    }
    func release() {
        let signal = lock.withLock { if released { return false }; released = true; return true }
        if signal { resume.signal() }
    }
    private func blockUntilEntered() -> Bool { entered.wait(timeout: .now() + 2) == .success }
    func waitUntilEntered() async -> Bool {
        await Task.detached { [self] in blockUntilEntered() }.value
    }
}
