import Foundation
import XCTest
@testable import MacScope

@MainActor
final class TypeAtlasSwiftObjCLinkTests: XCTestCase {
    private let command = "list-image-types"
    private let binaryID = UUID()
    private enum Route: CaseIterable { case inline, asynchronous, attached }
    private let l1: ScriptValue = .object([
        "linked": .int(1), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])

    private func read(_ route: Route, _ args: ScriptValue, _ api: WorkspaceScriptingAPI,
                      _ executor: MCPAttachExecutor) async throws -> ScriptValue {
        switch route {
        case .inline: return try api.execute(command, arguments: args)
        case .asynchronous: return try await api.executeAsync(command, arguments: args)
        case .attached: return try await executor.execute(command, args)
        }
    }
    private func direct(_ snap: WorkspaceSnapshot, _ args: ScriptValue = .object([:])) throws -> ScriptValue {
        try WorkspaceScriptingAPI.snapshotTypeListRead(command, arguments: args, snapshot: snap)
    }
    private func snapshot(_ analysis: ImageAnalysis) -> WorkspaceSnapshot {
        WorkspaceSnapshot(binaries: [BinaryImage(id: binaryID, name: "types", path: "/ignored/types",
            kind: "Mach-O", architecture: "arm64")], analysisBySlot: [.primary: analysis])
    }
    private func cached(_ entries: [TypeAtlasEntry]) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        return snapshot(analysis)
    }
    private func makeStore(_ snap: WorkspaceSnapshot) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "889 links", snapshot: snap, engine: AnalysisEngine(), autosaveScheduler: nil)
    }
    private func attachedExecutor(_ store: WorkspaceStore) -> MCPAttachExecutor {
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        return executor
    }
    private func selector(_ address: UInt64, kind: TypeAtlasKind) -> ExactClassReadSelector {
        .init(owner: .init(slot: .primary, binaryID: binaryID, architecture: "arm64", sliceIndex: nil,
                          ownerGeneration: 0), entryID: .init(slot: .primary, kind: kind, key: .address(address)))
    }
    private func entry(_ name: String, kind: TypeAtlasKind, address: UInt64) -> TypeAtlasEntry {
        .init(id: .init(slot: .primary, kind: kind, key: .address(address)), kind: kind,
              name: name, superclass: nil, members: [], conformances: [], methods: [], users: [], evidence: .descriptor)
    }
    private func fixture() -> [TypeAtlasEntry] {
        var objc = entry("_TtC4Test3Foo", kind: .objcClass, address: 0x7100)
        objc.instanceSize = 32
        objc.members = [
            .init(name: "count", type: nil, offset: 8, evidence: .descriptor, size: 8),
            .init(name: "label", type: nil, offset: 16, evidence: .descriptor, size: 16),
        ]
        var swift = entry("Foo", kind: .swiftClass, address: 0x8000)
        swift.qualifiedName = "Test.Foo"; swift.isGeneric = false; swift.isPrivateOrLocal = false
        swift.members = [
            .init(name: "count", type: "Swift.Int", offset: 8, evidence: .descriptor),
            .init(name: "label", type: "Swift.String", offset: 16, evidence: .descriptor),
        ]
        return [objc, swift]
    }
    private func object(_ value: ScriptValue) throws -> [String: ScriptValue] {
        guard case .object(let fields) = value else { throw ScriptingError.invalidArgument("expected test object") }
        return fields
    }
    private var objcID: ScriptValue { .object(["slot": .int(0), "kind": .string("objcClass"), "address": .hex(0x7100)]) }
    private var swiftID: ScriptValue { .object(["slot": .int(0), "kind": .string("swiftClass"), "address": .hex(0x8000)]) }
    private func linkedRows(_ entries: [TypeAtlasEntry], merge: Bool = true) throws -> [ScriptValue] {
        var objc = try object(WorkspaceScriptingAPI.typeAtlasEntryValue(entries[0]))
        var swift = try object(WorkspaceScriptingAPI.typeAtlasEntryValue(entries[1]))
        let objcIdentity = try XCTUnwrap(objc["id"])
        let swiftIdentity = try XCTUnwrap(swift["id"])
        objc["swiftName"] = entries[1].qualifiedName.map(ScriptValue.string); objc["swiftId"] = swiftIdentity
        swift["objcName"] = .string(entries[0].name); swift["objcId"] = objcIdentity
        if merge {
            let members = try XCTUnwrap(objc["members"]?.arrayValue)
            XCTAssertEqual(members.count, entries[1].members.count)
            objc["members"] = .array(try members.enumerated().map { index, value in
                var member = try object(value)
                member["swiftFieldType"] = entries[1].members[index].type.map(ScriptValue.string) ?? .null
                return .object(member)
            })
            swift["members"] = .array([]); swift["membersListedOn"] = objcIdentity
        }
        return [.object(objc), .object(swift)]
    }
    private func assertCounts(_ reply: ScriptValue, _ expected: ScriptValue, population: Int64,
                              file: StaticString = #filePath, line: UInt = #line) throws {
        let counts = try XCTUnwrap(reply["swiftObjCLinks"], file: file, line: line)
        XCTAssertEqual(counts, expected, file: file, line: line)
        let linked = try XCTUnwrap(counts["linked"]?.intValue, file: file, line: line)
        let abstained = try XCTUnwrap(counts["abstained"], file: file, line: line)
        var sum = linked
        for key in ["runtimeNameUndecodable", "noSwiftRow", "ambiguous", "privateOrLocal", "generic"] {
            sum += try XCTUnwrap(abstained[key]?.intValue, file: file, line: line)
        }
        XCTAssertEqual(sum, population, file: file, line: line)
    }
    private func checkUnlinked(_ entries: [TypeAtlasEntry], counts: ScriptValue, population: Int64) async throws {
        let snap = cached(entries)
        for route in Route.allCases {
            let store = makeStore(snap)
            let reply = try await read(route, .object([:]), WorkspaceScriptingAPI(store: store), attachedExecutor(store))
            XCTAssertEqual(reply["types"], .array(entries.map(WorkspaceScriptingAPI.typeAtlasEntryValue)))
            try assertCounts(reply, counts, population: population)
        }
    }

    func testF1LinkedFullRowsOnEveryRoute() async throws {
        let entries = fixture(), snap = cached(fixture())
        let expected = try linkedRows(entries)
        for route in Route.allCases {
            let store = makeStore(snap)
            let reply = try await read(route, .object([:]), WorkspaceScriptingAPI(store: store), attachedExecutor(store))
            XCTAssertEqual(reply["types"], .array(expected))
            XCTAssertEqual(reply["total"], .int(2))
            XCTAssertEqual(Set(try object(reply).keys), Set(["imageSlot", "imageOwner", "total", "types", "swiftObjCLinks"]))
            try assertCounts(reply, l1, population: 1)
        }
    }
    func testF2MembersListedOnceWithBothTypes() throws {
        let reply = try direct(cached(fixture()))
        let rows = try XCTUnwrap(reply["types"]?.arrayValue)
        let members = rows.flatMap { $0["members"]?.arrayValue ?? [] }
        XCTAssertEqual(members.count, 2)
        XCTAssertEqual(members.compactMap { $0["name"]?.stringValue }, ["count", "label"])
        XCTAssertEqual(members.compactMap { $0["swiftFieldType"] }, [.string("Swift.Int"), .string("Swift.String")])
        XCTAssertEqual(rows[1]["membersListedOn"], objcID)
        try assertCounts(reply, l1, population: 1)
    }
    private func mergeFixture(objc objcMembers: [TypeAtlasMember], swift swiftMembers: [TypeAtlasMember]) -> [TypeAtlasEntry] {
        var entries = fixture()
        entries[0].members = objcMembers
        entries[1].members = swiftMembers
        return entries
    }
    private func renderedMembers(_ reply: ScriptValue) throws -> [ScriptValue] {
        try XCTUnwrap(reply["types"]?.arrayValue).flatMap { $0["members"]?.arrayValue ?? [] }
    }
    private func membersNotMerged(_ reply: ScriptValue) -> Int64? { reply["swiftObjCLinks"]?["membersNotMerged"]?.intValue }

    /// B1: both sides carry no layout (offset nil, evidence unknown); the pair merges.
    func testB1UnknownLayoutPairMerges() throws {
        let entries = mergeFixture(
            objc: [.init(name: "count", type: nil, offset: nil, evidence: .unknown, size: 8),
                   .init(name: "label", type: nil, offset: nil, evidence: .unknown, size: 8)],
            swift: [.init(name: "count", type: "Swift.Int", offset: nil, evidence: .unknown),
                    .init(name: "label", type: "Swift.String", offset: nil, evidence: .unknown)])
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        XCTAssertEqual(links.byIndex[1]?.membersListedOn, true)
        XCTAssertEqual(links.counts?.membersNotMerged, 0)
        let reply = try direct(cached(entries))
        let members = try renderedMembers(reply)
        XCTAssertEqual(members.compactMap { $0["name"]?.stringValue }, ["count", "label"])
        XCTAssertEqual(members.compactMap { $0["swiftFieldType"] }, [.string("Swift.Int"), .string("Swift.String")])
        XCTAssertEqual(try XCTUnwrap(reply["types"]?.arrayValue)[1]["membersListedOn"], objcID)
        XCTAssertEqual(membersNotMerged(reply), 0)
    }

    /// B2: ObjC link-time offsets (descriptor) and a Swift member with no layout fact: merged, the ObjC row
    /// keeps its offsets and evidence and gains the Swift types.
    func testB2SwiftMemberWithoutLayoutMergesIntoObjCDescriptorMember() throws {
        let entries = mergeFixture(
            objc: [.init(name: "count", type: nil, offset: 8, evidence: .descriptor, size: 8),
                   .init(name: "label", type: nil, offset: 16, evidence: .descriptor, size: 16)],
            swift: [.init(name: "count", type: "Swift.Int", offset: nil, evidence: .unknown),
                    .init(name: "label", type: "Swift.String", offset: nil, evidence: .unknown)])
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        XCTAssertEqual(links.byIndex[1]?.membersListedOn, true)
        XCTAssertEqual(links.counts?.membersNotMerged, 0)
        let reply = try direct(cached(entries))
        let members = try renderedMembers(reply)
        XCTAssertEqual(members.count, 2)
        XCTAssertEqual(members.compactMap { $0["offset"] }, [.int(8), .int(16)])
        XCTAssertEqual(members.compactMap { $0["evidence"] }, [.string("descriptor"), .string("descriptor")])
        XCTAssertEqual(members.compactMap { $0["swiftFieldType"] }, [.string("Swift.Int"), .string("Swift.String")])
        XCTAssertEqual(membersNotMerged(reply), 0)
    }

    /// B3: both descriptor but the offsets disagree (24 vs 32): not merged, counted in membersNotMerged.
    func testB3DisagreeingOffsetsStayUnmerged() throws {
        let entries = mergeFixture(
            objc: [.init(name: "count", type: nil, offset: 24, evidence: .descriptor, size: 8)],
            swift: [.init(name: "count", type: "Swift.Int", offset: 32, evidence: .descriptor)])
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        XCTAssertEqual(links.byIndex[1]?.membersListedOn, false)
        XCTAssertEqual(links.counts?.membersNotMerged, 1)
        let reply = try direct(cached(entries))
        XCTAssertEqual(try renderedMembers(reply).count, 2)
        XCTAssertEqual(membersNotMerged(reply), 1)
    }

    func testF3FullAndNamesPagesOnEveryRoute() async throws {
        let entries = fixture(), snap = cached(fixture())
        let names: ScriptValue = .array([
            .object(["imageSlot": .int(0), "kind": .string("objcClass"), "name": .string("_TtC4Test3Foo"),
                     "id": objcID, "swiftName": .string("Test.Foo")]),
            .object(["imageSlot": .int(0), "kind": .string("swiftClass"), "name": .string("Foo"),
                     "id": swiftID, "qualifiedName": .string("Test.Foo"), "objcName": .string("_TtC4Test3Foo"),
                     "hasUnassignedSwiftConformanceRecords": .null]),
        ])
        for route in Route.allCases {
            for mode in ["full", "names"] {
                let store = makeStore(snap)
                let reply = try await read(route, .object(["page": .bool(true), "fields": .string(mode)]),
                    WorkspaceScriptingAPI(store: store), attachedExecutor(store))
                XCTAssertEqual(reply["rows"], mode == "names" ? names : .array(try linkedRows(entries)))
                XCTAssertEqual(reply["total"], .int(2))
                XCTAssertEqual(Set(try object(reply).keys), Set(["rows", "total", "isTruncated", "nextCursor",
                    "sourceComplete", "imageSlot", "imageOwner", "swiftObjCLinks"]))
                try assertCounts(reply, l1, population: 1)
            }
        }
    }
    func testF4FiltersDoNotChangeLinksOrCounts() async throws {
        let entries = fixture(), snap = cached(fixture())
        let expected = try linkedRows(entries)
        for route in Route.allCases {
            for (args, key, rows) in [
                (ScriptValue.object(["kind": .string("swiftClass")]), "types", [expected[1]]),
                (.object(["kind": .string("objcClass")]), "types", [expected[0]]),
                (.object(["page": .bool(true), "name": .string("Test.Foo")]), "rows", [expected[1]]),
                (.object(["page": .bool(true), "nameContains": .string("Test.Foo")]), "rows", [expected[1]]),
            ] {
                let store = makeStore(snap)
                let reply = try await read(route, args, WorkspaceScriptingAPI(store: store), attachedExecutor(store))
                XCTAssertEqual(reply[key], .array(rows)); XCTAssertEqual(reply["total"], .int(1))
                try assertCounts(reply, l1, population: 1)
            }
        }
    }
    func testF5UncachedBuilderProducesTheSamePair() throws {
        var analysis = ImageAnalysis()
        analysis.objcClasses = [ObjCClass(name: "_TtC4Test3Foo", superclassName: nil, adoptedProtocols: [],
            classMethods: [], instanceMethods: [], ivars: [
                ObjCIvar(name: "count", typeEncoding: nil, offset: 8, size: 8),
                ObjCIvar(name: "label", typeEncoding: nil, offset: 16, size: 16),
            ], properties: [], address: 0x7100, instanceSize: 32)]
        analysis.swiftTypes = [SwiftTypeDescriptor(kind: .class, name: "Foo", fields: [
            SwiftField(name: "count", typeName: "Swift.Int", byteOffset: 8),
            SwiftField(name: "label", typeName: "Swift.String", byteOffset: 16),
        ], descriptorAddress: 0x8000, qualifiedName: "Test.Foo", isGeneric: false, isPrivateOrLocal: false)]
        var entries = fixture(); entries[1].swiftMethodTableResolved = false
        entries[1].hasUnassignedSwiftConformanceRecords = false
        let reply = try direct(snapshot(analysis))
        XCTAssertEqual(reply["types"], .array(try linkedRows(entries)))
        try assertCounts(reply, l1, population: 1)
    }
    private func checkNoPopulation(_ entries: [TypeAtlasEntry]) async throws {
        let snap = cached(entries)
        let expected: ScriptValue = .object(["imageSlot": .int(0), "imageOwner": .string(binaryID.uuidString),
            "total": .int(Int64(entries.count)), "types": .array(entries.map(WorkspaceScriptingAPI.typeAtlasEntryValue))])
        for route in Route.allCases {
            let store = makeStore(snap)
            let api = WorkspaceScriptingAPI(store: store)
            let reply = try await read(route, .object([:]), api, attachedExecutor(store))
            XCTAssertEqual(reply, expected); XCTAssertNil(reply["swiftObjCLinks"])
            let page = try await read(route, .object(["page": .bool(true)]), api, attachedExecutor(store))
            XCTAssertEqual(Set(try object(page).keys), Set(["rows", "total", "isTruncated", "nextCursor",
                "sourceComplete", "imageSlot", "imageOwner"]))
            XCTAssertEqual(page["rows"], .array(entries.map(WorkspaceScriptingAPI.typeAtlasEntryValue)))
            XCTAssertNil(page["swiftObjCLinks"])
        }
    }
    func testC1PureObjCUnchanged() async throws {
        var s = entry("S", kind: .objcClass, address: 0x7100)
        s.members = [.init(name: "_n", type: "i", offset: 8, evidence: .descriptor, size: 4)]
        try await checkNoPopulation([s])
    }
    func testC2PureSwiftStructUnchanged() async throws {
        var p = entry("P", kind: .swiftStruct, address: 0x8000)
        p.qualifiedName = "Test.P"
        p.members = [.init(name: "v", type: "Int", offset: nil, evidence: .unknown)]
        try await checkNoPopulation([p])
    }
    func testC3AmbiguousSwiftSide() async throws {
        var entries = fixture()
        var other = entries[1]; other.id.key = .address(0x8100)
        entries.append(other)
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(1),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testC4AmbiguousObjCSide() async throws {
        var entries = fixture()
        var other = entries[0]; other.id.key = .address(0x7200)
        entries.insert(other, at: 1)
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(2),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 2)
    }
    func testC5PrivateRuntimeNameUndecodable() async throws {
        let entries = [entry("_TtC5MintsP33_3208C1554E1B9481C4EE6F26EE266FA019ResourceBundleClass", kind: .objcClass, address: 0x7300)]
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(1), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testC6StructIsNotSwiftClassCandidate() async throws {
        let objc = entry("_TtC4Test3Bar", kind: .objcClass, address: 0x7400)
        var swift = entry("Bar", kind: .swiftStruct, address: 0x8200)
        swift.qualifiedName = "Test.Bar"
        let entries = [objc, swift]
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(1), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testC7PrivateSwiftRow() async throws {
        var entries = fixture(); entries[1].isPrivateOrLocal = true
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(1), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testC8GenericSwiftRow() async throws {
        var entries = fixture(); entries[1].isGeneric = true
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(1),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testC12GenericRuntimeNameIsInPopulation() async throws {
        let entries = [entry("_TtGC4Test3BoxSi_", kind: .objcClass, address: 0x7500)]
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(1), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testMissingPrivacyFlagAbstains() async throws {
        var entries = fixture(); entries[1].isPrivateOrLocal = nil
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(1), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testMissingGenericFlagAbstains() async throws {
        var entries = fixture(); entries[1].isGeneric = nil
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(1),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testPrivacyPrecedesGeneric() async throws {
        var entries = fixture(); entries[1].isPrivateOrLocal = true; entries[1].isGeneric = true
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(1), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testNoSwiftRowPrecedesObjCAmbiguity() async throws {
        let objc = fixture()[0]
        var other = objc; other.id.key = .address(0x7200)
        let entries = [objc, other]
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(2), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 2)
    }
    func testQualifiedNameIsCaseSensitive() async throws {
        var entries = fixture(); entries[1].qualifiedName = "test.Foo"
        let counts: ScriptValue = .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(1), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        try await checkUnlinked(entries, counts: counts, population: 1)
    }
    func testC9DifferentMemberListsKeepBoth() async throws {
        var entries = fixture()
        entries[1].members[1] = .init(name: "extra", type: "Swift.Int", offset: 24, evidence: .descriptor)
        let counts: ScriptValue = .object(["linked": .int(1), "membersNotMerged": .int(1), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        let expected = try linkedRows(entries, merge: false)
        for route in Route.allCases {
            let store = makeStore(cached(entries))
            let reply = try await read(route, .object([:]), WorkspaceScriptingAPI(store: store), attachedExecutor(store))
            XCTAssertEqual(reply["types"], .array(expected))
            XCTAssertNil(reply["types"]?.arrayValue?[1]["membersListedOn"])
            try assertCounts(reply, counts, population: 1)
        }
    }
    func testC10ExactClassReadKeepsOriginalRows() throws {
        let entries = fixture(), snap = cached(fixture())
        for (index, address, kind) in [(0, UInt64(0x7100), TypeAtlasKind.objcClass), (1, 0x8000, .swiftClass)] {
            let reply = try WorkspaceScriptingAPI.exactClassRead(selector: selector(address, kind: kind), snapshot: snap)
            XCTAssertEqual(reply["status"], .string("found"))
            XCTAssertEqual(reply["class"], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[index]))
            XCTAssertNil(reply["swiftObjCLinks"])
        }
    }
    func testC11RoutesAgreeInFullAndPageModes() async throws {
        let snap = cached(fixture())
        for args in [ScriptValue.object([:]), .object(["page": .bool(true)])] {
            let store = makeStore(snap)
            let api = WorkspaceScriptingAPI(store: store)
            let expected = try api.execute(command, arguments: args)
            for route in Route.allCases {
                let reply = try await read(route, args, api, attachedExecutor(store))
                XCTAssertEqual(reply, expected)
                if reply["swiftObjCLinks"] != nil { try assertCounts(reply, l1, population: 1) }
            }
        }
    }
    func testStrictDecoderWitnesses() {
        XCTAssertEqual(SwiftDemangler.demangleLegacyClassName("_TtC4Test3Foo"), "Test.Foo")
        XCTAssertEqual(SwiftDemangler.demangleLegacyClassName("_TtCC4Test5Outer5Inner"), "Test.Outer.Inner")
        XCTAssertEqual(SwiftDemangler.demangleLegacyClassName("_TtC5Mints14ViewController"), "Mints.ViewController")
        for name in ["_TtC04Test3Foo", "_TtC4Test3FooJunk", "_TtGC4Test3BoxSi_",
                     "_TtC5MintsP33_3208C1554E1B9481C4EE6F26EE266FA019ResourceBundleClass"] {
            XCTAssertNil(SwiftDemangler.demangleLegacyClassName(name))
        }
    }
    func testBothEmptyMemberListsStayEmptyWithoutRedirection() throws {
        var entries = fixture(); entries[0].members = []; entries[1].members = []
        let reply = try direct(cached(entries))
        XCTAssertEqual(reply["types"], .array(try linkedRows(entries, merge: false)))
        try assertCounts(reply, l1, population: 1)
    }
    func testOneEmptyOrReorderedMemberListIsNotMerged() throws {
        let counts: ScriptValue = .object(["linked": .int(1), "membersNotMerged": .int(1), "abstained": .object([
            "runtimeNameUndecodable": .int(0), "noSwiftRow": .int(0), "ambiguous": .int(0),
            "privateOrLocal": .int(0), "generic": .int(0),
        ])])
        for empty in [true, false] {
            var entries = fixture()
            if empty { entries[1].members = [] } else { entries[1].members.reverse() }
            let reply = try direct(cached(entries))
            XCTAssertEqual(reply["types"], .array(try linkedRows(entries, merge: false)))
            try assertCounts(reply, counts, population: 1)
        }
    }
    func testUnknownSwiftFieldTypeStaysNull() throws {
        var entries = fixture(); entries[1].members[0].type = nil
        let reply = try direct(cached(entries))
        XCTAssertEqual(reply["types"]?.arrayValue?[0]["members"]?.arrayValue?[0]["swiftFieldType"], .null)
        XCTAssertEqual(reply["types"]?.arrayValue?[1]["members"], .array([]))
        try assertCounts(reply, l1, population: 1)
    }
    func testCountsAndLinksPersistAcrossCursorAndZeroLimit() async throws {
        let snap = cached(fixture())
        let expected = try linkedRows(fixture())
        for route in Route.allCases {
            let store = makeStore(snap)
            let api = WorkspaceScriptingAPI(store: store)
            let first = try await read(route, .object(["page": .bool(true), "limit": .int(1)]), api, attachedExecutor(store))
            XCTAssertEqual(first["rows"], .array([expected[0]]))
            try assertCounts(first, l1, population: 1)
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let second = try await read(route, .object(["page": .bool(true), "limit": .int(1), "cursor": .string(cursor)]), api, attachedExecutor(store))
            XCTAssertEqual(second["rows"], .array([expected[1]]))
            XCTAssertEqual(second["isTruncated"], .bool(false))
            try assertCounts(second, l1, population: 1)
            let zero = try await read(route, .object(["limit": .int(0)]), api, attachedExecutor(store))
            XCTAssertEqual(zero["types"], .array([])); XCTAssertEqual(zero["total"], .int(2))
            try assertCounts(zero, l1, population: 1)
        }
    }
    func testLinkedNamesSurviveNodeAndByteFallbacks() throws {
        for reason in ["nodes", "bytes"] {
            var entries = fixture()
            if reason == "nodes" {
                entries[0].methods = Array(repeating: TypeAtlasMethod(name: "method", implementation: nil), count: 6_000)
            } else {
                entries[0].methods = [.init(name: String(repeating: "x", count: 300_000), implementation: nil)]
            }
            let reply = try direct(cached(entries), .object(["page": .bool(true), "limit": .int(1)]))
            let row = try XCTUnwrap(reply["rows"]?.arrayValue?.first)
            XCTAssertEqual(row["fullRowOmitted"], .bool(true))
            XCTAssertEqual(row["fullRowReason"], .string(reason))
            XCTAssertEqual(row["swiftName"], .string("Test.Foo"))
            XCTAssertNil(row["swiftId"]); XCTAssertNotNil(reply["nextCursor"]?.stringValue)
            try assertCounts(reply, l1, population: 1)
        }
    }

    // Item 1248: Swift/ObjC row-identity controls.
    // These fixtures isolate row identity; the existing member-name predicate is unchanged.
    private func counts1248(ambiguous: Int64 = 0, undecodable: Int64 = 0,
                            noSwift: Int64 = 0) -> ScriptValue {
        .object(["linked": .int(0), "membersNotMerged": .int(0), "abstained": .object([
            "runtimeNameUndecodable": .int(undecodable), "noSwiftRow": .int(noSwift),
            "ambiguous": .int(ambiguous), "privateOrLocal": .int(0), "generic": .int(0),
        ])])
    }

    // Independent expected projection for these short, untruncated fixture names.
    private func namesRow1248(_ entry: TypeAtlasEntry) throws -> ScriptValue {
        let full = try object(WorkspaceScriptingAPI.typeAtlasEntryValue(entry))
        var row: [String: ScriptValue] = [:]
        for key in ["id", "imageSlot", "kind", "name"] { row[key] = full[key] }
        if entry.kind == .swiftClass {
            row["qualifiedName"] = full["qualifiedName"]
            row["hasUnassignedSwiftConformanceRecords"] = full["hasUnassignedSwiftConformanceRecords"]
        }
        return .object(row)
    }

    private func checkUnlinked1248(_ entries: [TypeAtlasEntry], snapshot supplied: WorkspaceSnapshot? = nil,
                                   counts: ScriptValue, population: Int64) async throws {
        let snap = supplied ?? cached(entries)
        for route in Route.allCases {
            for mode in ["unpaged", "full", "names"] {
                let args: ScriptValue = mode == "unpaged" ? .object([:])
                    : .object(["page": .bool(true), "fields": .string(mode)])
                let store = makeStore(snap)
                let reply = try await read(route, args, WorkspaceScriptingAPI(store: store), attachedExecutor(store))
                let expected = mode == "names" ? try entries.map { try namesRow1248($0) }
                    : entries.map(WorkspaceScriptingAPI.typeAtlasEntryValue)
                XCTAssertEqual(reply[mode == "unpaged" ? "types" : "rows"], .array(expected))
                XCTAssertEqual(reply["total"], .int(Int64(entries.count)))
                try assertCounts(reply, counts, population: population)
            }
        }
    }

    // both original member arrays survive, including the unlinked Other.Foo row.
    func test1248DistinctQualifiedClassesWithSharedFallbackIDDoNotLink() async throws {
        var entries = fixture()
        entries[1].id.key = .name("Foo")
        var other = entries[1]; other.qualifiedName = "Other.Foo"
        entries.append(other)
        try await checkUnlinked1248(entries, counts: counts1248(ambiguous: 1), population: 1)
    }

    // conformance-owner ambiguity does not itself protect link identities.
    func test1248DuplicateSwiftDescriptorAddressesDoNotLink() async throws {
        var entries = fixture()
        var other = entries[1]; other.qualifiedName = "Other.Foo"
        entries.append(other)
        try await checkUnlinked1248(entries, counts: counts1248(ambiguous: 1), population: 1)
    }

    // count conflicting ObjC IDs even outside the _Tt link population.
    func test1248SharedObjCAddressInsideAndOutsidePopulationDoesNotLink() async throws {
        for inside in [false, true] {
            var entries = fixture()
            var other = entries[0]
            other.name = inside ? "_TtC5Other3Foo" : "OtherClass"
            entries.append(other)
            if inside {
                var swift = entries[1]
                swift.id.key = .address(0x8100); swift.qualifiedName = "Other.Foo"
                entries.append(swift)
            }
            let population: Int64 = inside ? 2 : 1
            try await checkUnlinked1248(entries, counts: counts1248(ambiguous: population), population: population)
        }
    }

    // supported model inputs, not only manually colliding cached rows.
    func test1248BuilderProducesFallbackAndDescriptorCollisions() async throws {
        for address in [nil, UInt64(0x8000)] as [UInt64?] {
            var analysis = ImageAnalysis()
            analysis.objcClasses = [ObjCClass(name: "_TtC4Test3Foo", superclassName: nil,
                adoptedProtocols: [], classMethods: [], instanceMethods: [], ivars: [
                    ObjCIvar(name: "count", typeEncoding: nil, offset: 8, size: 8),
                    ObjCIvar(name: "label", typeEncoding: nil, offset: 16, size: 16),
                ], properties: [], address: 0x7100, instanceSize: 32)]
            analysis.swiftTypes = ["Test.Foo", "Other.Foo"].map { qualifiedName in
                SwiftTypeDescriptor(kind: .class, name: "Foo", fields: [
                    SwiftField(name: "count", typeName: "Swift.Int", byteOffset: 8),
                    SwiftField(name: "label", typeName: "Swift.String", byteOffset: 16),
                ], descriptorAddress: address, qualifiedName: qualifiedName,
                    isGeneric: false, isPrivateOrLocal: false)
            }
            let catalog = ImageTypeCatalogBuilder.build(analysis: analysis)
            let swift = catalog.entries.filter { $0.kind == .swiftClass }
            XCTAssertEqual(swift.count, 2)
            XCTAssertEqual(swift.first?.id, swift.last?.id)
            let expectedKey: TypeAtlasEntryID.Key = address.map { .address($0) } ?? .name("Foo")
            XCTAssertEqual(swift.first?.id.key, expectedKey)
            XCTAssertNil(analysis.typeCatalog)
            try await checkUnlinked1248(catalog.entries, snapshot: snapshot(analysis),
                counts: counts1248(ambiguous: 1), population: 1)
        }
    }

    // the existing ObjC name-fallback collision was already name-ambiguous.
    func test1248DuplicateObjCNameFallbackRemainsAmbiguous() async throws {
        var entries = fixture()
        entries[0].id.key = .name(entries[0].name)
        entries.append(entries[0])
        try await checkUnlinked1248(entries, counts: counts1248(ambiguous: 2), population: 2)
    }

    // retain exact positive full/names shapes on all three routes.
    func test1248UniqueNameFallbackStillLinksAndListsMembersOnce() async throws {
        var entries = fixture(); entries[1].id.key = .name("Foo")
        var full = try linkedRows(entries)
        var objc = try object(full[0])
        objc["swiftId"] = .object(["slot": .int(0), "kind": .string("swiftClass"), "name": .string("Foo")])
        full[0] = .object(objc)
        var objcNames = try object(namesRow1248(entries[0]))
        var swiftNames = try object(namesRow1248(entries[1]))
        objcNames["swiftName"] = .string("Test.Foo")
        swiftNames["objcName"] = .string("_TtC4Test3Foo")
        let names: [ScriptValue] = [.object(objcNames), .object(swiftNames)]
        for route in Route.allCases {
            for mode in ["unpaged", "full", "names"] {
                let store = makeStore(cached(entries))
                let args: ScriptValue = mode == "unpaged" ? .object([:])
                    : .object(["page": .bool(true), "fields": .string(mode)])
                let reply = try await read(route, args, WorkspaceScriptingAPI(store: store), attachedExecutor(store))
                let rows = try XCTUnwrap(reply[mode == "unpaged" ? "types" : "rows"]?.arrayValue)
                XCTAssertEqual(rows, mode == "names" ? names : full)
                if mode != "names" {
                    XCTAssertEqual(rows.flatMap { $0["members"]?.arrayValue ?? [] }.count, 2)
                    XCTAssertEqual(rows[1]["membersListedOn"], objcID)
                }
                try assertCounts(reply, l1, population: 1)
            }
        }
    }

    // existing undecodable/no-row priority stays ahead of identity ambiguity;
    // identity ambiguity, like name ambiguity, stays ahead of private/generic flags.
    func test1248IdentityAbstentionPrecedence() async throws {
        for flags in [(true, false), (false, true), (true, true)] {
            var entries = fixture(); entries[1].id.key = .name("Foo")
            entries[1].isPrivateOrLocal = flags.0; entries[1].isGeneric = flags.1
            var other = entries[1]; other.qualifiedName = "Other.Foo"
            entries.append(other)
            try await checkUnlinked1248(entries, counts: counts1248(ambiguous: 1), population: 1)
        }
        var absent = fixture()[0]; absent.id.key = .name(absent.name)
        try await checkUnlinked1248([absent, absent], counts: counts1248(noSwift: 2), population: 2)
        var invalid = absent; invalid.name = "_TtC4Test3FooJunk"; invalid.id.key = .name(invalid.name)
        try await checkUnlinked1248([invalid, invalid], counts: counts1248(undecodable: 2), population: 2)
    }

    // same-stamp cache injection is distinct from a builder-produced catalog.
    func test1248SplitSlotsAbstainDirectlyAndThroughSameStampCache() async throws {
        var entries = fixture(); entries[1].id.slot = ImageSlot(rawValue: 1)
        let catalog = ImageTypeCatalog(slot: .primary, entries: entries)
        XCTAssertEqual(catalog.restamped(to: .primary), catalog)
        XCTAssertEqual(cached(entries).typeCatalog(in: .primary).entries, entries)
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        XCTAssertTrue(links.byIndex.isEmpty)
        let counts = try XCTUnwrap(links.counts)
        try assertCounts(.object(["swiftObjCLinks": WorkspaceScriptingAPI.typeAtlasLinkCountsValue(counts)]),
            counts1248(ambiguous: 1), population: 1)
        try await checkUnlinked1248(entries, counts: counts1248(ambiguous: 1), population: 1)
    }

    // identical names/addresses in separate images do not compete; both IDs restamp.
    func test1248RestampedImagePairKeepsBothSerializedSlots() async throws {
        let otherSlot = ImageSlot(rawValue: 1), otherOwner = UUID()
        var analysis = ImageAnalysis()
        analysis.typeCatalog = ImageTypeCatalog(slot: .primary, entries: fixture())
        let snap = WorkspaceSnapshot(binaries: [
            BinaryImage(id: binaryID, name: "primary", path: "/ignored/primary", kind: "Mach-O",
                architecture: "arm64", slot: .primary),
            BinaryImage(id: otherOwner, name: "other", path: "/ignored/other", kind: "Mach-O",
                architecture: "arm64", slot: otherSlot),
        ], analysisBySlot: [.primary: analysis, otherSlot: analysis])
        for route in Route.allCases {
            for slot in [ImageSlot.primary, otherSlot] {
                for paged in [false, true] {
                    let store = makeStore(snap)
                    let reply = try await read(route, .object([
                        "image": .int(Int64(slot.rawValue)), "page": .bool(paged),
                    ]), WorkspaceScriptingAPI(store: store), attachedExecutor(store))
                    let rows = try XCTUnwrap(reply[paged ? "rows" : "types"]?.arrayValue)
                    let expectedSwiftID: ScriptValue = .object([
                        "slot": .int(Int64(slot.rawValue)), "kind": .string("swiftClass"), "address": .hex(0x8000)])
                    let expectedObjCID: ScriptValue = .object([
                        "slot": .int(Int64(slot.rawValue)), "kind": .string("objcClass"), "address": .hex(0x7100)])
                    XCTAssertEqual(rows.count, 2)
                    XCTAssertEqual(rows.first?["swiftId"], expectedSwiftID)
                    XCTAssertEqual(rows.last?["objcId"], expectedObjCID)
                    XCTAssertEqual(rows.last?["membersListedOn"], expectedObjCID)
                    XCTAssertEqual(rows.last?["members"], .array([]))
                    XCTAssertEqual(reply["imageSlot"], .int(Int64(slot.rawValue)))
                    XCTAssertEqual(reply["imageOwner"], .string((slot == .primary ? binaryID : otherOwner).uuidString))
                    try assertCounts(reply, l1, population: 1)
                }
            }
        }
    }

    // filtering never hides a conflicting ID from the uniqueness count.
    func test1248CollisionCountsUseWholeCatalogBeforeFilterAndCursor() async throws {
        var entries = fixture(); entries[1].id.key = .name("Foo")
        var other = entries[1]; other.qualifiedName = "Other.Foo"; entries.append(other)
        let expected = entries.map(WorkspaceScriptingAPI.typeAtlasEntryValue)
        for route in Route.allCases {
            let store = makeStore(cached(entries)), counts = counts1248(ambiguous: 1)
            let api = WorkspaceScriptingAPI(store: store), executor = attachedExecutor(store)
            let filtered = try await read(route, .object(["page": .bool(true), "name": .string("Test.Foo")]), api, executor)
            XCTAssertEqual(filtered["rows"], .array([expected[1]]))
            try assertCounts(filtered, counts, population: 1)
            let first = try await read(route, .object(["page": .bool(true), "limit": .int(1)]), api, executor)
            XCTAssertEqual(first["rows"], .array([expected[0]]))
            try assertCounts(first, counts, population: 1)
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let second = try await read(route, .object(["page": .bool(true), "limit": .int(1), "cursor": .string(cursor)]), api, executor)
            XCTAssertEqual(second["rows"], .array([expected[1]]))
            try assertCounts(second, counts, population: 1)
        }
    }

    // the existing omission projection keeps its shape but adds no false counterpart.
    func test1248CollisionLeavesOversizedNamesFallbackUnlinked() throws {
        for reason in ["nodes", "bytes"] {
            var entries = fixture(); entries[1].id.key = .name("Foo")
            var other = entries[1]; other.qualifiedName = "Other.Foo"; entries.append(other)
            if reason == "nodes" {
                entries[0].methods = Array(repeating: TypeAtlasMethod(name: "method", implementation: nil), count: 6_000)
            } else {
                entries[0].methods = [.init(name: String(repeating: "x", count: 300_000), implementation: nil)]
            }
            var expected = try object(namesRow1248(entries[0]))
            expected["fullRowOmitted"] = .bool(true); expected["fullRowReason"] = .string(reason)
            let reply = try direct(cached(entries), .object(["page": .bool(true), "limit": .int(1)]))
            XCTAssertEqual(reply["rows"], .array([.object(expected)]))
            try assertCounts(reply, counts1248(ambiguous: 1), population: 1)
        }
    }

    // transport harness follows supplied MCPServerTests without private test helpers.
    func test1248MCPTransportPreservesCollisionRows() async throws {
        var entries = fixture(); entries[1].id.key = .name("Foo")
        var other = entries[1]; other.qualifiedName = "Other.Foo"; entries.append(other)
        for route in Route.allCases {
            for paged in [false, true] {
                let store = makeStore(cached(entries)), api = WorkspaceScriptingAPI(store: store)
                let server: MCPServer
                switch route {
                case .inline, .asynchronous: server = MCPServer(api: api)
                case .attached:
                    let executor = attachedExecutor(store)
                    server = MCPServer(api: api, configuration: .attached,
                        asyncCommandExecutor: { try await executor.execute($0, $1) },
                        allowedCommands: MCPAttachExecutor.attachCommands)
                }
                let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
                    "method": .string("tools/call"), "params": .object([
                        "name": .string(command), "arguments": .object(["page": .bool(paged)]),
                    ])])
                let data = try request.jsonData()
                let response: Data?
                switch route {
                case .inline: response = server.handleMessage(data)
                case .asynchronous, .attached: response = await server.handleMessageAsync(data)
                }
                let envelope = try ScriptValue.decode(XCTUnwrap(response))
                XCTAssertNil(envelope["error"])
                XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
                let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                let reply = try ScriptValue.decode(Data(text.utf8))
                XCTAssertEqual(reply[paged ? "rows" : "types"], .array(entries.map(WorkspaceScriptingAPI.typeAtlasEntryValue)))
                try assertCounts(reply, counts1248(ambiguous: 1), population: 1)
            }
        }
    }

    func testLinkedNameAdmissionPreservesLengthAndScalarBoundary() throws {
        let id = TypeAtlasEntryID(slot: .primary, kind: .swiftClass, key: .address(0x8000))
        func project(_ name: String) throws -> ScriptValue {
            let link = WorkspaceScriptingAPI.TypeAtlasSwiftObjCLink(isObjC: true, otherName: name, otherID: id)
            return try WorkspaceScriptingAPI.applyingTypeAtlasLink(.object([:]), link: link, namesOnly: true, checkpoint: {})
        }
        let exact = String(repeating: "a", count: 8_191) + "é" + "x"
        let value = try project(exact)
        XCTAssertEqual(value["swiftName"], .string(String(repeating: "a", count: 8_191)))
        XCTAssertEqual(value["swiftNameTruncated"], .bool(true))
        XCTAssertEqual(value["swiftNameByteLength"], .int(8_194))
        let boundary = try project(String(repeating: "a", count: 16_384))
        XCTAssertEqual(boundary["swiftNameByteLength"], .int(16_384))
        XCTAssertThrowsError(try project(String(repeating: "a", count: 16_385))) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else {
                return XCTFail("Expected a structured budget refusal")
            }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget?.limit, 16_384)
            XCTAssertEqual(refusal.used, 16_385)
        }
    }
}

extension TypeAtlasSwiftObjCLinkTests {
    // Item 1180: linked layout preservation and bounded output admission controls.
    private func checkLayoutRows(_ entries: [TypeAtlasEntry], merge: Bool) async throws {
        var counts = try object(l1)
        counts["membersNotMerged"] = .int(merge ? 0 : 1)
        let expected = try linkedRows(entries, merge: merge)
        for route in Route.allCases {
            for paged in [false, true] {
                let store = makeStore(cached(entries))
                let args: ScriptValue = paged ? .object(["page": .bool(true)]) : .object([:])
                let reply = try await read(route, args, WorkspaceScriptingAPI(store: store), attachedExecutor(store))
                XCTAssertEqual(reply[paged ? "rows" : "types"], .array(expected))
                try assertCounts(reply, .object(counts), population: 1)
            }
        }
    }

    func test1180EqualKnownLayoutAndBothUnknownLayoutOnEveryRoute() async throws {
        var equal = fixture()
        equal[1].members[0].size = 8
        equal[1].members[1].size = 16
        try await checkLayoutRows(equal, merge: true)
        var unknown = fixture()
        for row in unknown.indices {
            for member in unknown[row].members.indices {
                unknown[row].members[member].offset = nil
                unknown[row].members[member].size = nil
                unknown[row].members[member].evidence = .unknown
            }
        }
        try await checkLayoutRows(unknown, merge: true)
    }

    func test1180MissingAndConflictingObjCSizeKeepBothRowsOnEveryRoute() async throws {
        let sizes: [UInt64?] = [nil, 4]
        for objcSize in sizes {
            var entries = fixture()
            entries[0].members[0].size = objcSize
            entries[1].members[0].size = 8
            try await checkLayoutRows(entries, merge: false)
        }
    }

    func test1180DuplicateAndEmptyMemberNamesDoNotMergeOnEveryRoute() async throws {
        for names in [["count", "count"], ["", "label"]] {
            var entries = fixture()
            for row in entries.indices {
                for member in entries[row].members.indices { entries[row].members[member].name = names[member] }
            }
            try await checkLayoutRows(entries, merge: false)
        }
    }

    private func importedMember1180(
        archive: String = "synthetic-archive", declaration: String = "int", field: String = "field-0",
        bitOffset: UInt64? = 64, bitWidth: UInt64? = 3, flexible: Bool = false, anonymous: Bool = false
    ) -> ImportedTypeMemberMetadata {
        .init(fieldID: field, typeIdentity: .init(archiveSHA256: archive, declarationID: declaration),
              absoluteBitOffset: bitOffset, bitWidth: bitWidth, flexibleArray: flexible, anonymous: anonymous)
    }

    func test1180ImportedIdentityAndBitMetadataMustSurviveOnEveryRoute() async throws {
        let retained = importedMember1180()
        var equal = fixture()
        for row in equal.indices {
            equal[row].members[0].imported = retained
            equal[row].members[0].evidence = .compilerImport
        }
        try await checkLayoutRows(equal, merge: true)
        let alternatives: [ImportedTypeMemberMetadata?] = [
            nil, importedMember1180(archive: "other-synthetic-archive"),
            importedMember1180(declaration: "uint"), importedMember1180(field: "field-1"),
            importedMember1180(bitOffset: 65), importedMember1180(bitOffset: nil),
            importedMember1180(bitWidth: 4), importedMember1180(bitWidth: nil),
            importedMember1180(flexible: true), importedMember1180(anonymous: true),
        ]
        for metadata in alternatives {
            var entries = equal
            entries[0].members[0].imported = metadata
            try await checkLayoutRows(entries, merge: false)
        }
    }

    func test1180ConflictRetainsBothPagesAndFilterIdentityOnEveryRoute() async throws {
        var entries = fixture()
        entries[1].members[0].offset = 24
        let expected = try linkedRows(entries, merge: false)
        var counts = try object(l1); counts["membersNotMerged"] = .int(1)
        for route in Route.allCases {
            let store = makeStore(cached(entries))
            let api = WorkspaceScriptingAPI(store: store)
            let executor = attachedExecutor(store)
            let first = try await read(route, .object(["page": .bool(true), "limit": .int(1)]), api, executor)
            XCTAssertEqual(first["rows"], .array([expected[0]]))
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let second = try await read(route, .object(["page": .bool(true), "limit": .int(1),
                "cursor": .string(cursor)]), api, executor)
            XCTAssertEqual(second["rows"], .array([expected[1]]))
            XCTAssertEqual(second["nextCursor"], .null)
            let filtered = try await read(route, .object(["page": .bool(true),
                "kind": .string("swiftClass")]), api, executor)
            XCTAssertEqual(filtered["rows"], .array([expected[1]]))
            for reply in [first, second, filtered] { try assertCounts(reply, .object(counts), population: 1) }
        }
    }

    func test1180LinksStayWithinSelectedImageAndUseRestampedIdentity() async throws {
        let secondSlot = ImageSlot(rawValue: 1)
        let secondID = UUID()
        var primaryAnalysis = ImageAnalysis(), secondaryAnalysis = ImageAnalysis()
        primaryAnalysis.typeCatalog = .init(slot: .primary, entries: fixture())
        var secondEntries = fixture()
        secondEntries[1].members[0].offset = 24
        // Cached catalogs are primary-stamped; snapshot.typeCatalog must restamp both identities.
        secondaryAnalysis.typeCatalog = .init(slot: .primary, entries: secondEntries)
        let snap = WorkspaceSnapshot(binaries: [
            BinaryImage(id: binaryID, name: "first", path: "/ignored/first", kind: "Mach-O", architecture: "arm64", slot: .primary),
            BinaryImage(id: secondID, name: "second", path: "/ignored/second", kind: "Mach-O", architecture: "arm64", slot: secondSlot),
        ], analysisBySlot: [.primary: primaryAnalysis, secondSlot: secondaryAnalysis])
        for row in secondEntries.indices { secondEntries[row].id.slot = secondSlot }
        let expectedSecond = try linkedRows(secondEntries, merge: false)
        var counts = try object(l1); counts["membersNotMerged"] = .int(1)
        for route in Route.allCases {
            for paged in [false, true] {
                let store = makeStore(snap)
                let api = WorkspaceScriptingAPI(store: store)
                let executor = attachedExecutor(store)
                let args: ScriptValue = .object(["image": .int(1), "page": .bool(paged)])
                let reply = try await read(route, args, api, executor)
                XCTAssertEqual(reply[paged ? "rows" : "types"], .array(expectedSecond))
                XCTAssertEqual(reply["imageSlot"], .int(1))
                XCTAssertEqual(reply["imageOwner"], .string(secondID.uuidString))
                try assertCounts(reply, .object(counts), population: 1)
                let primary = try await read(route, .object(["image": .int(0), "page": .bool(paged)]), api, executor)
                XCTAssertEqual(primary[paged ? "rows" : "types"], .array(try linkedRows(fixture())))
                try assertCounts(primary, l1, population: 1)
            }
        }
    }

    private func manyLongLinkedNames1180() -> [TypeAtlasEntry] {
        (0..<64).flatMap { index -> [TypeAtlasEntry] in
            // 596+4 chars: 128 unlinked rows stay under defaultTypeAtlasEscapedRowCap (166_000,
            // 864b91eab, #395; 1,000-char names crossed it and returned 89 rows), while the linked
            // projection (about 7 name copies per pair) still exceeds the 262_144-byte text budget.
            let name = String(repeating: "A", count: 596) + String(format: "%04d", index)
            let objc = entry("_TtC4Test\(name.count)" + name, kind: .objcClass, address: UInt64(0x10000 + index * 16))
            var swift = entry(name, kind: .swiftClass, address: UInt64(0x20000 + index * 16))
            swift.qualifiedName = "Test." + name
            swift.isGeneric = false; swift.isPrivateOrLocal = false
            return [objc, swift]
        }
    }

    private func assertLinkBudget1180(_ error: Error, file: StaticString = #filePath, line: UInt = #line) {
        guard case ScriptingError.structuredRefusal(let refusal) = error else {
            return XCTFail("Expected linked projection budget refusal", file: file, line: line)
        }
        XCTAssertEqual(refusal.code, .budgetExceeded, file: file, line: line)
        XCTAssertEqual(refusal.narrowing, ["page"], file: file, line: line)
        XCTAssertTrue(refusal.detail.contains("page:true"), file: file, line: line)
    }

    func test1180AddedLinkedNamesAreAdmittedBeforeBoundedRows() async throws {
        let entries = manyLongLinkedNames1180(), snap = cached(manyLongLinkedNames1180())
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        XCTAssertEqual(links.counts?.linked, 64)
        // Control: the original catalog is below the old aggregate text/node limits.
        let unlinked = try WorkspaceScriptingAPI.snapshotTypeListRead(command, arguments: .object([:]),
            snapshot: snap, swiftObjCLinks: false)
        XCTAssertEqual(unlinked["types"]?.arrayValue?.count, 128)
        XCTAssertNil(unlinked["swiftObjCLinks"])
        // Post-864b91eab (#395, dot 1281): over-cap linked unpaged replies return a truncated page
        // (isTruncated + nextCursor) instead of throwing budgetExceeded. Linked names are still
        // kept (linked == 64); the bounded rows are what get truncated.
        func assertTruncatedLinked(_ reply: ScriptValue, file: StaticString = #filePath, line: UInt = #line) {
            let count = reply["types"]?.arrayValue?.count ?? 0
            XCTAssertEqual(reply["isTruncated"], .bool(true), file: file, line: line)
            XCTAssertTrue(count > 0 && count < 128, "rows \(count)", file: file, line: line)
            XCTAssertNotNil(reply["nextCursor"]?.stringValue, file: file, line: line)
            XCTAssertEqual(reply["swiftObjCLinks"]?["linked"], .int(64), file: file, line: line)
        }
        assertTruncatedLinked(try direct(snap))
        for route in [Route.asynchronous, .attached] {
            let store = makeStore(snap)
            assertTruncatedLinked(try await read(route, .object([:]), WorkspaceScriptingAPI(store: store),
                attachedExecutor(store)))
        }
        // Legacy inline unpaged behavior follows the same truncated-page contract; page mode is the bounded escape hatch.
        let store = makeStore(snap)
        assertTruncatedLinked(try WorkspaceScriptingAPI(store: store).execute(command))
        for route in Route.allCases {
            let routeStore = makeStore(snap)
            let page = try await read(route, .object(["page": .bool(true), "fields": .string("names"),
                "limit": .int(1)]), WorkspaceScriptingAPI(store: routeStore), attachedExecutor(routeStore))
            XCTAssertEqual(page["rows"]?.arrayValue?.count, 1)
            XCTAssertEqual(page["swiftObjCLinks"]?["linked"], .int(64))
            XCTAssertNotNil(page["nextCursor"]?.stringValue)
        }
    }

    func test1180LinkedNameIdentityIsAdmittedAndPageNamesRemainAvailable() throws {
        var entries = fixture()
        entries[1].id.key = .name(String(repeating: "x", count: 2_049))
        let snap = cached(entries)
        let unlinked = try WorkspaceScriptingAPI.snapshotTypeListRead(command, arguments: .object([:]),
            snapshot: snap, swiftObjCLinks: false)
        XCTAssertEqual(unlinked["types"]?.arrayValue?.count, 2)
        XCTAssertThrowsError(try direct(snap)) { assertLinkBudget1180($0) }
        let page = try direct(snap, .object(["page": .bool(true), "fields": .string("names")]))
        XCTAssertEqual(page["rows"]?.arrayValue?.count, 2)
        XCTAssertEqual(page["nextCursor"], .null)
    }

    func test1180LinkAdmissionChargesIdentityRedirectionAndCopiedTypes() throws {
        let id = TypeAtlasEntryID(slot: .primary, kind: .objcClass, key: .name("ObjC"))
        let links = WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks(byIndex: [
            0: .init(isObjC: false, otherName: "ObjC", otherID: id, membersListedOn: true),
            1: .init(isObjC: true, otherName: "Swift", otherID: id, swiftFieldTypes: [nil, "Swift.Int"]),
        ])
        var budget = AttachedTypeReadBudget()
        try budget.take(4_096 - 4) // Needs three identities plus two copied-type nodes: five.
        XCTAssertThrowsError(try budget.links(links, checkpoint: {})) {
            XCTAssertEqual($0 as? ScriptingError, AttachedTypeReadBudget.refused)
        }
        var visits = 0, cancelled = AttachedTypeReadBudget()
        XCTAssertThrowsError(try cancelled.links(links, checkpoint: {
            visits += 1; throw CancellationError()
        })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(visits, 1)
    }

    func testConflictingSwiftLayoutRemainsVisibleOnBothLinkedRows() throws {
        var entries = fixture()
        entries[1].members[1].offset = 24
        for paged in [false, true] {
            let args: ScriptValue = paged ? .object(["page": .bool(true)]) : .object([:])
            let reply = try direct(cached(entries), args)
            let rows = try XCTUnwrap(reply[paged ? "rows" : "types"]?.arrayValue)
            XCTAssertEqual(rows, try linkedRows(entries, merge: false))
            XCTAssertEqual(rows[1]["members"], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[1])["members"])
            XCTAssertNil(rows[1]["membersListedOn"])
        }
    }

    func testDistinctSwiftMemberEvidenceRemainsVisible() throws {
        var entries = fixture()
        entries[1].members[1].evidence = .staticEvaluation
        let reply = try direct(cached(entries))
        let rows = try XCTUnwrap(reply["types"]?.arrayValue)
        XCTAssertEqual(rows, try linkedRows(entries, merge: false))
        XCTAssertEqual(rows[1]["members"], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[1])["members"])
    }

    func testMissingObjCOffsetDoesNotHideKnownSwiftOffset() throws {
        var entries = fixture()
        entries[0].members[1].offset = nil
        entries[0].members[1].evidence = .unknown
        let reply = try direct(cached(entries))
        let rows = try XCTUnwrap(reply["types"]?.arrayValue)
        XCTAssertEqual(rows, try linkedRows(entries, merge: false))
        XCTAssertEqual(rows[1]["members"], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[1])["members"])
    }
}
