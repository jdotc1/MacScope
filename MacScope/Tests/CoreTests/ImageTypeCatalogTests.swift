import XCTest
@testable import MacScope

/// RX-02a: the Type Atlas engine seam (`MacScopeAnalysisCore.ImageTypeCatalog`), the `classref`
/// xref projection, the additive layout fields it reads, and the read-only `list-image-types`
/// command (scripting API and MCP).
@MainActor
final class ImageTypeCatalogTests: XCTestCase {

    // MARK: - Real fixtures (compiled on the host; skipped without xcrun)

    /// An ObjC executable whose `main` uses the same-image `Widget` directly (`adrp`+`add` to its
    /// `class_t`), the external `NSMutableArray` (a GOT bind under ld-prime), and sends
    /// `computeValue` through an inline selref load (selector stubs off).
    func testCatalogOverRealObjCFixtureCarriesLayoutUsersAndIMPs() throws {
        let url = try HostFixture.objc("""
        #import <Foundation/Foundation.h>
        @protocol Pinger <NSObject>
        - (void)ping;
        @optional + (int)version;
        @property(nonatomic) int level;
        @end
        @interface Widget : NSObject <Pinger> { @public int _count; double _ratio; }
        - (int)computeValue;
        @end
        @implementation Widget
        - (void)ping {}
        - (int)computeValue { return _count * 7 + 1; }
        + (instancetype)make { return [self new]; }
        @end
        @interface Child : Widget @end
        @implementation Child
        - (int)computeValue { return [super computeValue] + 1; }
        @end
        int main(void) {
            Child *child = [Child new];
            Widget *w = [Widget new];
            NSMutableArray *list = [NSMutableArray new];
            return [w computeValue] + [child computeValue] + (int)list.count;
        }
        """)
        let machO = try MachOParser().parse(Data(contentsOf: url))
        let loaded = try MachOBinaryLoader().load(at: url)
        XCTAssertFalse(machO.objectiveCMetadata.superclassReferences.isEmpty)
        for reference in machO.objectiveCMetadata.superclassReferences {
            XCTAssertNotNil(loaded.objcClassReferences[reference.sourceAddress], "superrefs reach the Atlas reference map")
        }
        let snapshot = try AnalysisEngine().analyze(url: url)
        let slot = snapshot.primarySlot
        let analysis = try XCTUnwrap(snapshot.analysis(in: slot))
        XCTAssertNotNil(analysis.typeCatalog, "the image part is built once at analysis time")

        // ld-prime (Xcode 15+) folds `__objc_classrefs` into GOT binds and direct class_t
        // references, so a freshly linked fixture has no classref slots; any classref xref the
        // engine does emit must land in a slot the loader projected.
        let classrefs = analysis.xrefs.filter { $0.kind == XRefKind.classref }
        XCTAssertTrue(classrefs.allSatisfy { analysis.objcClassReferences[$0.to] != nil })

        let catalog = snapshot.typeCatalog(in: slot)
        let widget = try XCTUnwrap(catalog.entries(named: "Widget").first { $0.kind == .objcClass })
        let widgetClass = try XCTUnwrap(analysis.objcClasses.first { $0.name == "Widget" })
        let classAddress = try XCTUnwrap(widgetClass.address, "class_t address is kept")
        XCTAssertEqual(widget.id, TypeAtlasEntryID(slot: slot, kind: .objcClass, key: .address(classAddress)))
        XCTAssertEqual(widget.superclass, "NSObject")
        XCTAssertEqual(widget.evidence, .descriptor)
        XCTAssertTrue(widget.conformances.contains("Pinger"))
        XCTAssertEqual(widget.instanceSize, 24, "isa + int (padded) + double")

        // ivar_t offsets/sizes: recorded link-time descriptor values.
        let members = Dictionary(uniqueKeysWithValues: widget.members.map { ($0.name, $0) })
        XCTAssertEqual(members["_count"]?.offset, 8)
        XCTAssertEqual(members["_count"]?.size, 4)
        XCTAssertEqual(members["_count"]?.type, "int")
        XCTAssertEqual(members["_count"]?.evidence, .descriptor)
        XCTAssertEqual(members["_ratio"]?.offset, 16)
        XCTAssertEqual(members["_ratio"]?.size, 8)
        XCTAssertEqual(widget.members.count, 2)
        XCTAssertTrue(widget.members.allSatisfy { $0.evidence == .descriptor })

        // Users: main's direct reference to the class object; methods carry IMPs and selref users.
        XCTAssertFalse(widget.users.isEmpty, "main references Widget's class_t")
        let directUses = Set(analysis.xrefs.filter { $0.kind == XRefKind.data && $0.to == classAddress }.map(\.from))
        XCTAssertEqual(Set(widget.users), directUses)
        let compute = try XCTUnwrap(widget.methods.first { $0.name == "computeValue" })
        XCTAssertNotNil(compute.implementation)
        XCTAssertFalse(compute.isClassMethod)
        XCTAssertFalse(compute.selectorUsers.isEmpty, "main loads the computeValue selref")
        XCTAssertEqual(widget.methods.first { $0.name == "make" }?.isClassMethod, true)

        // Protocol objects have descriptor identities and honest requirement methods.
        let pinger = try XCTUnwrap(catalog.entries(named: "Pinger").first)
        XCTAssertEqual(pinger.kind, .objcProtocol)
        let proto = try XCTUnwrap(analysis.objcProtocols.first { $0.name == "Pinger" })
        XCTAssertEqual(pinger.id.key, .address(proto.address))
        XCTAssertEqual(pinger.evidence, .descriptor)
        XCTAssertEqual(pinger.conformances, ["NSObject"])
        XCTAssertEqual(pinger.methods.first { $0.name == "ping" }?.isOptionalRequirement, false)
        XCTAssertEqual(pinger.methods.first { $0.name == "version" }?.isOptionalRequirement, true)
        XCTAssertEqual(pinger.methods.first { $0.name == "version" }?.isClassMethod, true)
        XCTAssertTrue(pinger.methods.allSatisfy { $0.implementation == nil })
        XCTAssertEqual(proto.properties.map(\.name), ["level"])
        XCTAssertEqual(pinger.declaredProperties?.map(\.name), ["level"])
        XCTAssertTrue(pinger.members.isEmpty)
    }

    /// A Swift dylib: static struct vectors carry descriptor offsets; generics stay unknown.
    func testSwiftStaticStructOffsetsAndUnknownGenericLayout() throws {
        let data = try HostFixture.swiftDylib("""
        public protocol Shape { var area: Double { get } }
        public struct Point: Shape { public let x: Int; public let y: Double; public var area: Double { 0 } }
        public final class Box { var count: Int32 = 0 }
        public struct Generic<T> { public let value: T; public let tail: Int }
        public enum Color { case red, green }
        """)
        let machO = try MachOParser().parse(data)
        var analysis = ImageAnalysis()
        analysis.swiftTypes = machO.swiftTypes
        analysis.swiftConformances = machO.swiftConformances
        let catalog = ImageTypeCatalogBuilder.build(analysis: analysis, slot: .primary)

        let point = try XCTUnwrap(catalog.entries(named: "Point").first)
        XCTAssertEqual(point.kind, .swiftStruct)
        let descriptor = try XCTUnwrap(machO.swiftTypes.first { $0.name == "Point" }?.descriptorAddress)
        XCTAssertEqual(point.id.key, .address(descriptor))
        XCTAssertEqual(point.evidence, .descriptor)
        XCTAssertEqual(point.members.map(\.name), ["x", "y"])
        XCTAssertEqual(point.members.map(\.type), ["Int", "Double"])
        XCTAssertEqual(point.members.map(\.offset), [0, 8])
        XCTAssertTrue(point.members.allSatisfy { $0.evidence == .descriptor })
        let generic = try XCTUnwrap(catalog.entries(named: "Generic").first)
        XCTAssertTrue(generic.members.allSatisfy { $0.offset == nil && $0.evidence == .unknown })
        XCTAssertEqual(point.conformances, ["Shape"])
        XCTAssertEqual(catalog.entries(named: "Box").first?.kind, .swiftClass)
        XCTAssertEqual(catalog.entries(named: "Color").first?.kind, .swiftEnum)
        XCTAssertEqual(catalog.entries(named: "Color").first?.members.map(\.name), ["red", "green"])
    }

    // MARK: - classref projection (resolver, deterministic)

    private func conformanceDisclosureSnapshot(fields: [SwiftField] = []) -> WorkspaceSnapshot {
        var primary = ImageAnalysis()
        primary.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "Shared", fields: fields,
                                                 descriptorAddress: 0x1100)]
        primary.swiftConformances = [SwiftConformance(typeName: "Shared", protocolName: "External")]
        var sibling = ImageAnalysis()
        sibling.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "Shared", fields: fields,
                                                 descriptorAddress: 0x1100)]
        sibling.swiftConformances = [SwiftConformance(typeName: "Shared", protocolName: "Local",
                                                     typeDescriptorAddress: 0x1100)]
        return WorkspaceSnapshot(
            binaries: [
                BinaryImage(id: UUID(), name: "primary", path: "/tmp/primary", kind: "Mach-O",
                            architecture: "arm64", slot: .primary),
                BinaryImage(id: UUID(), name: "sibling", path: "/tmp/sibling", kind: "Mach-O",
                            architecture: "arm64", slot: ImageSlot(rawValue: 1)),
            ],
            analysisBySlot: [.primary: primary, ImageSlot(rawValue: 1): sibling]
        )
    }

    func testConformanceDisclosureSurvivesNamesProjectionPerImage() throws {
        let snapshot = conformanceDisclosureSnapshot()
        for image in 0...1 {
            for fields in ["full", "names"] {
                let page = try XCTUnwrap(WorkspaceScriptingAPI.typeAtlasPage(.object([
                    "page": .bool(true), "image": .int(Int64(image)), "fields": .string(fields),
                ]), snapshot: snapshot, checkpoint: {}, swiftObjCLinks: false))
                let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
                XCTAssertEqual(row["hasUnassignedSwiftConformanceRecords"], .bool(image == 0))
                XCTAssertEqual(row["imageSlot"], .int(Int64(image)))
                XCTAssertEqual(row["id"]?["slot"], .int(Int64(image)))
                XCTAssertEqual(page["sourceComplete"], .null)
                if fields == "full" {
                    XCTAssertEqual(row["conformances"], .array(image == 0 ? [] : [.string("Local")]))
                } else {
                    XCTAssertNil(row["conformances"], "names projection does not invent a detail list")
                }
            }
        }
    }

    func testConformanceDisclosureSurvivesBothOversizedRowFallbacks() throws {
        let nodeFields = Array(repeating: SwiftField(name: "member", typeName: "Int"),
                               count: WorkspaceScriptingAPI.maximumTypeAtlasRowNodes / 15 + 1)
        let byteFields = [SwiftField(name: String(repeating: "x",
                                                 count: WorkspaceScriptingAPI.maximumListPageBytes + 1),
                                     typeName: "Int")]
        for (reason, fields) in [("nodes", nodeFields), ("bytes", byteFields)] {
            let snapshot = conformanceDisclosureSnapshot(fields: fields)
            for image in 0...1 {
                let page = try XCTUnwrap(WorkspaceScriptingAPI.typeAtlasPage(.object([
                    "page": .bool(true), "image": .int(Int64(image)), "fields": .string("full"),
                ]), snapshot: snapshot, checkpoint: {}, swiftObjCLinks: false))
                let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
                XCTAssertEqual(row["fullRowOmitted"], .bool(true))
                XCTAssertEqual(row["fullRowReason"], .string(reason))
                XCTAssertEqual(row["hasUnassignedSwiftConformanceRecords"], .bool(image == 0))
                XCTAssertEqual(row["imageSlot"], .int(Int64(image)))
                XCTAssertEqual(page["sourceComplete"], .null)
            }
        }
    }

    func testConformanceDisclosureOnCommandAndSnapshotRoutes() async throws {
        let snapshot = conformanceDisclosureSnapshot()
        let store = WorkspaceStore(workspaceName: "1233 conformance disclosure", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        for image in 0...1 {
            for fields: String? in [nil, "full", "names"] {
                var arguments: [String: ScriptValue] = ["image": .int(Int64(image))]
                if let fields { arguments["fields"] = .string(fields) }
                let args = ScriptValue.object(arguments)
                let inline = try api.execute("list-image-types", arguments: args)
                let asynchronous = try await api.executeAsync("list-image-types", arguments: args)
                let attached = try WorkspaceScriptingAPI.snapshotListRead(
                    "list-image-types", arguments: args, snapshot: snapshot, scope: .attached)
                for value in [inline, asynchronous, attached] {
                    let row = try XCTUnwrap(value[fields == nil ? "types" : "rows"]?.arrayValue?.first)
                    XCTAssertEqual(row["hasUnassignedSwiftConformanceRecords"], .bool(image == 0))
                    XCTAssertEqual(row["imageSlot"], .int(Int64(image)))
                    XCTAssertEqual(value["imageSlot"], .int(Int64(image)))
                }
            }
        }
    }

    func testLegacySwiftNamesStayNullAndNonSwiftNamesStayUnchanged() throws {
        let entries = TypeAtlasKind.allCases.map { kind in
            TypeAtlasEntry(id: .init(slot: .primary, kind: kind, key: .name(kind.rawValue)),
                           kind: kind, name: kind.rawValue, superclass: nil, members: [],
                           conformances: [], methods: [], users: [], evidence: .unknown)
        }
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        let snapshot = WorkspaceSnapshot(binaries: [
            BinaryImage(id: UUID(), name: "legacy", path: "/tmp/legacy", kind: "Mach-O", architecture: "arm64"),
        ], analysisBySlot: [.primary: analysis])
        let page = try XCTUnwrap(WorkspaceScriptingAPI.typeAtlasPage(.object([
            "page": .bool(true), "fields": .string("names"),
        ]), snapshot: snapshot, checkpoint: {}, swiftObjCLinks: false))
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.count, entries.count)
        for (entry, row) in zip(entries, rows) {
            guard case .object(let fields) = row else { return XCTFail("expected names row") }
            switch entry.kind {
            case .swiftClass, .swiftStruct, .swiftEnum:
                XCTAssertEqual(row["hasUnassignedSwiftConformanceRecords"], .null)
                XCTAssertEqual(Set(fields.keys), Set(["id", "imageSlot", "kind", "name",
                                                      "qualifiedName", "hasUnassignedSwiftConformanceRecords"]))
            default:
                XCTAssertNil(row["hasUnassignedSwiftConformanceRecords"])
                XCTAssertEqual(Set(fields.keys), Set(["id", "imageSlot", "kind", "name"]))
            }
        }
    }

    func testConformanceOwnerInputChangesInvalidateCachedDisclosure() throws {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "Owner", descriptorAddress: 0x1100)]
        analysis.swiftConformances = [SwiftConformance(typeName: "Owner", protocolName: "P",
                                                      typeDescriptorAddress: 0x1100)]
        analysis.refreshTypeCatalog()
        XCTAssertEqual(analysis.typeCatalog?.entries.first?.hasUnassignedSwiftConformanceRecords, false)
        analysis.swiftConformances.append(SwiftConformance(typeName: "Owner", protocolName: "External"))
        XCTAssertNil(analysis.typeCatalog)
        analysis.refreshTypeCatalog()
        XCTAssertEqual(analysis.typeCatalog?.entries.first?.hasUnassignedSwiftConformanceRecords, true)
        analysis.swiftTypes.append(SwiftTypeDescriptor(kind: .struct, name: "Duplicate", descriptorAddress: 0x1100))
        XCTAssertNil(analysis.typeCatalog)
        analysis.refreshTypeCatalog()
        let rows = try XCTUnwrap(analysis.typeCatalog?.entries)
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.allSatisfy { $0.conformances.isEmpty && $0.hasUnassignedSwiftConformanceRecords == true })
    }

    func testRealMixedSwiftObjCFixtureCarriesClassAndConformanceMethods() throws {
        let data = try HostFixture.swiftDylib("""
        import Foundation
        public protocol Runner { func run() -> Int }
        public class Base: Runner { public func run() -> Int { 1 }; public class func version() -> Int { 2 } }
        public class Child: Base { public override func run() -> Int { 3 } }
        @objc public class Bridge: NSObject { @objc public func ping() -> Int { 4 } }
        public struct Pair { public let first: Int; public let second: Double }
        """)
        let machO = try MachOParser().parse(data)
        var analysis = ImageAnalysis()
        analysis.swiftTypes = machO.swiftTypes
        analysis.swiftConformances = machO.swiftConformances
        analysis.objcClasses = machO.objectiveCMetadata.classes
        let catalog = ImageTypeCatalogBuilder.build(analysis: analysis)
        let base = try XCTUnwrap(catalog.entries(named: "Base").first { $0.kind == .swiftClass })
        XCTAssertFalse(base.methods.isEmpty)
        XCTAssertEqual(base.swiftMethodTableResolved, true)
        XCTAssertTrue(base.methods.contains { $0.isClassMethod && $0.implementation != nil })
        XCTAssertTrue(base.methods.contains { !$0.isClassMethod && $0.implementation != nil })
        // MachOParser runs SW4 annotatingMethodSymbols (SwiftMetadataParser.swift:54), so the decider
        // (SwiftMetadataModel.swift:337, `implementationSymbol?.name ?? label`) names a slot only when it found
        // exactly one symbol and otherwise yields the positional label. The catalog must equal the decider
        // (ImageTypeCatalog.swift:327); the symbol-less control is the synthetic SW4/SW4B1 tests below.
        XCTAssertTrue(base.methods.allSatisfy { $0.swiftMetadata != nil && $0.name == $0.swiftMetadata?.name })
        XCTAssertTrue(base.methods.allSatisfy { $0.swiftMetadata?.implementationSymbol != nil || $0.name.contains("name unknown") })
        let runner = try XCTUnwrap(base.swiftConformanceMethods?.first { $0.protocolName == "Runner" })
        XCTAssertNotNil(runner.descriptorAddress)
        XCTAssertTrue(runner.methods?.contains { $0.implementation != nil } == true)
        let child = try XCTUnwrap(catalog.entries(named: "Child").first { $0.kind == .swiftClass })
        XCTAssertTrue(child.methods.contains { $0.swiftMetadata?.source == .override && $0.implementation != nil })
        let objc = try XCTUnwrap(catalog.entries.first { $0.kind == .objcClass && $0.methods.contains { $0.name == "ping" } })
        XCTAssertNotNil(objc.methods.first { $0.name == "ping" }?.implementation)
        XCTAssertTrue(objc.methods.allSatisfy { $0.swiftMetadata == nil })
        XCTAssertEqual(catalog.entries(named: "Pair").first?.members.map(\.offset), [0, 8])
    }

    /// SW1C receipt on a real compiled dylib: expected offsets come from the language's size/alignment ABI
    /// (GT-A, `MemoryLayout`), and the ObjC `ivar_list_t` offsets are the independent second path (GT-B).
    /// Skipped (NOT a pass) when xcrun cannot compile.
    func testRealCompiledClassFieldOffsetsMatchSizeAlignmentAndObjCIvars() throws {
        let data = try HostFixture.swiftDylib("""
        import Foundation
        public class A { public var a: Int = 1; public var b: Int32 = 2; public var c: Double = 3; public var d: Bool = false }
        public final class B: A { public var e: Int64 = 4; public var f: Int8 = 5 }
        public class N: NSObject { public var x: Int = 6; public var y: Int16 = 7 }
        public class G<T> { public var t: T? = nil; public var n: Int = 0 }
        """)
        let machO = try MachOParser().parse(data)
        func layout(start: UInt64, _ fields: [(size: Int, alignment: Int)]) -> [UInt64?] {
            var cursor = start
            return fields.map { field in
                cursor = (cursor + UInt64(field.alignment) - 1) / UInt64(field.alignment) * UInt64(field.alignment)
                defer { cursor += UInt64(field.size) }
                return cursor
            }
        }
        func offsets(_ name: String) throws -> [UInt64?] {
            let type = try XCTUnwrap(machO.swiftTypes.first { $0.name == name && $0.kind == .class }, name)
            return type.fields.map(\.byteOffset)
        }
        let a = layout(start: 16, [(MemoryLayout<Int>.size, MemoryLayout<Int>.alignment),
                                   (MemoryLayout<Int32>.size, MemoryLayout<Int32>.alignment),
                                   (MemoryLayout<Double>.size, MemoryLayout<Double>.alignment),
                                   (MemoryLayout<Bool>.size, MemoryLayout<Bool>.alignment)])
        XCTAssertEqual(try offsets("A"), a, "GT-A")
        // GT-B: the ObjC ivar offsets of the same class (read from the compiler's offset variables).
        let parser = try MachOParser().makeSwiftMetadataParser(in: data, file: machO)
        func ivarOffsets(_ name: String) throws -> [UInt64?] {
            let type = try XCTUnwrap(machO.swiftTypes.first { $0.name == name && $0.kind == .class })
            let metadata = try XCTUnwrap(type.descriptorAddress.flatMap { parser.classMetadataByDescriptor[$0] }, name)
            let objc = try XCTUnwrap(machO.objectiveCMetadata.classes.first { $0.address == metadata }, name)
            return objc.ivars.map(\.offset)
        }
        XCTAssertEqual(try ivarOffsets("A"), a, "GT-B")
        // N is NSObject-rooted: its offsets are kept only when vector == GT-A == ivars (Q1 B). Anything else
        // must be wholly unknown. Which of the two happened is reported in the log line below.
        let n = layout(start: 8, [(MemoryLayout<Int>.size, MemoryLayout<Int>.alignment),
                                  (MemoryLayout<Int16>.size, MemoryLayout<Int16>.alignment)])
        let nVector = try offsets("N")
        print("SW1C_N_OUTCOME vector=\(nVector) gtA=\(n) ivars=\(try ivarOffsets("N"))")
        if nVector.contains(where: { $0 != nil }) {
            XCTAssertEqual(nVector, n, "NSObject-rooted offsets disagree with GT-A: switch to unknown (Q1 A)")
            XCTAssertEqual(try ivarOffsets("N"), n)
        } else {
            XCTAssertEqual(nVector, [nil, nil])
        }
        // Q8 A: a Swift superclass keeps the class unknown. Generic classes are never static.
        XCTAssertEqual(try offsets("B"), [nil, nil])
        XCTAssertEqual(try offsets("G"), [nil, nil])
    }

    func testUniqueSwiftConformancesPreserveSourceOrder() throws {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [SwiftTypeDescriptor(kind: .class, name: "Only", descriptorAddress: 0x1100)]
        analysis.swiftConformances = [
            SwiftConformance(typeName: "Only", protocolName: "Legacy"),
            SwiftConformance(typeName: "Only", protocolName: "Exact", typeDescriptorAddress: 0x1100),
            SwiftConformance(typeName: "Only", protocolName: "Second", typeDescriptorAddress: 0x1100),
        ]
        let catalog = ImageTypeCatalogBuilder.build(analysis: analysis)
        let row = try XCTUnwrap(catalog.entries.first { $0.id.key == .address(0x1100) })
        XCTAssertEqual(row.conformances, ["Exact", "Second"])
        XCTAssertEqual(row.hasUnassignedSwiftConformanceRecords, true)
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(row)["hasUnassignedSwiftConformanceRecords"], .bool(true))
    }

    func testDuplicateSwiftDescriptorDoesNotClaimConformanceOwner() {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [
            SwiftTypeDescriptor(kind: .class, name: "First", descriptorAddress: 0x1100),
            SwiftTypeDescriptor(kind: .class, name: "Second", descriptorAddress: 0x1100),
        ]
        analysis.swiftConformances = [SwiftConformance(typeName: "First", protocolName: "P",
                                                      typeDescriptorAddress: 0x1100)]
        let catalog = ImageTypeCatalogBuilder.build(analysis: analysis)
        let rows = catalog.entries.filter { $0.kind == .swiftClass }
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.allSatisfy { $0.conformances.isEmpty })
        XCTAssertTrue(rows.allSatisfy { $0.swiftConformanceMethods == nil })
        XCTAssertTrue(rows.allSatisfy { $0.hasUnassignedSwiftConformanceRecords == true })
    }

    func testExternalNameOnlyConformanceDoesNotAttachToLocalType() throws {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "Shared", descriptorAddress: 0x1100,
                                                   qualifiedName: "Alpha.Shared")]
        analysis.swiftConformances = [SwiftConformance(typeName: "Shared", protocolName: "ForeignOnly",
                                                      typeQualifiedName: "Beta.Shared")]
        let row = try XCTUnwrap(ImageTypeCatalogBuilder.build(analysis: analysis).entries.first)
        XCTAssertEqual(row.qualifiedName, "Alpha.Shared")
        XCTAssertTrue(row.conformances.isEmpty)
        XCTAssertEqual(row.hasUnassignedSwiftConformanceRecords, true)
    }

    func testAssignedConformanceRecordsDoNotClaimUnassignedEvidence() throws {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "Only", descriptorAddress: 0x1100)]
        analysis.swiftConformances = [SwiftConformance(typeName: "Only", protocolName: "P",
                                                      typeDescriptorAddress: 0x1100)]
        let row = try XCTUnwrap(ImageTypeCatalogBuilder.build(analysis: analysis).entries.first)
        XCTAssertEqual(row.conformances, ["P"])
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(row)["hasUnassignedSwiftConformanceRecords"], .bool(false))
    }

    func testUnmodeledDescriptorLeavesConformanceUnassigned() throws {
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [
            SwiftTypeDescriptor(kind: .struct, name: "Visible", descriptorAddress: 0x1100),
            SwiftTypeDescriptor(kind: .unknown, name: "Unmodeled", descriptorAddress: 0x2200),
        ]
        analysis.swiftConformances = [SwiftConformance(typeName: "Unmodeled", protocolName: "P",
                                                      typeDescriptorAddress: 0x2200)]
        let row = try XCTUnwrap(ImageTypeCatalogBuilder.build(analysis: analysis).entries.first)
        XCTAssertEqual(row.name, "Visible")
        XCTAssertEqual(row.hasUnassignedSwiftConformanceRecords, true)
    }

    func testSwiftMethodGroupsUseDescriptorIdentityAndPreserveUnknownAndDuplicateTargets() throws {
        let first = SwiftMetadataMethod(source: .vtable, index: 0, descriptorAddress: 0x1110, implementation: 0x9000, flags: 0x10)
        let second = SwiftMetadataMethod(source: .vtable, index: 1, descriptorAddress: 0x1118, implementation: 0x9000, flags: 0x10)
        let witness = SwiftMetadataMethod(source: .witness, index: 0, descriptorAddress: 0x3000, implementation: nil, flags: 0x11)
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [
            SwiftTypeDescriptor(kind: .class, name: "Same", descriptorAddress: 0x1100, methods: [first, second]),
            SwiftTypeDescriptor(kind: .class, name: "Same", descriptorAddress: 0x2200),
        ]
        analysis.swiftConformances = [
            SwiftConformance(typeName: "Same", protocolName: "Known", descriptorAddress: 0x4000,
                             typeDescriptorAddress: 0x1100, methods: [witness]),
            SwiftConformance(typeName: "Same", protocolName: "Unknown", descriptorAddress: 0x4100,
                             typeDescriptorAddress: 0x2200),
            SwiftConformance(typeName: "Same", protocolName: "NameOnly", methods: [witness]),
        ]
        let catalog = ImageTypeCatalogBuilder.build(analysis: analysis)
        let one = try XCTUnwrap(catalog.entries.first { $0.id.key == .address(0x1100) })
        let two = try XCTUnwrap(catalog.entries.first { $0.id.key == .address(0x2200) })
        XCTAssertEqual(one.conformances, ["Known"])
        XCTAssertEqual(two.conformances, ["Unknown"])
        XCTAssertFalse(one.conformances.contains("NameOnly"))
        XCTAssertFalse(two.conformances.contains("NameOnly"))
        XCTAssertEqual(one.methods.map(\.implementation), [0x9000, 0x9000], "different slots may share code")
        XCTAssertEqual(one.swiftConformanceMethods?.map(\.protocolName), ["Known"])
        XCTAssertNil(one.swiftConformanceMethods?.first?.methods?.first?.implementation)
        XCTAssertEqual(two.swiftConformanceMethods?.map(\.protocolName), ["Unknown"])
        XCTAssertNil(two.swiftConformanceMethods?.first?.methods)
        XCTAssertEqual(two.swiftMethodTableResolved, false)
        XCTAssertTrue(two.methods.isEmpty)
        XCTAssertEqual(try JSONDecoder().decode(TypeAtlasEntry.self, from: JSONEncoder().encode(one)), one)

        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "methods", path: "/tmp/methods", kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: analysis]
        )
        let payload = AnalysisPayloadCodec.payload(from: snapshot)
        let decoded = try JSONDecoder().decode(AnalysisResultPayload.self, from: JSONEncoder().encode(payload))
        XCTAssertEqual(decoded.swiftTypes, payload.swiftTypes)
        XCTAssertEqual(decoded.swiftConformances, payload.swiftConformances)
        let legacyType = try JSONDecoder().decode(SwiftTypeDescriptor.self, from: Data(#"{"kind":"class","name":"Old","fields":[]}"#.utf8))
        let legacyConformance = try JSONDecoder().decode(SwiftConformance.self, from: Data(#"{"typeName":"Old","protocolName":"P"}"#.utf8))
        XCTAssertNil(legacyType.methods)
        XCTAssertNil(legacyConformance.methods)
        XCTAssertNil(legacyConformance.typeDescriptorAddress)
    }

    func testClassrefSlotLoadIsClassifiedAsClassrefNotData() {
        func row(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
            InstructionRow(address: address, bytes: "", mnemonic: mnemonic, operands: operands,
                           hasBreakpoint: false, comment: nil)
        }
        let rows = [
            row(0x1000, "adrp", "x8, 0x4000"),
            row(0x1004, "ldr", "x0, [x8, #0x10]"),   // classref slot 0x4010
            row(0x1008, "ldr", "x1, [x8, #0x18]"),   // selref slot 0x4018
            row(0x100c, "ldr", "x2, [x8, #0x20]"),   // plain data 0x4020
        ]
        let ranges = [DataCrossReferenceResolver.DataRange(lowerBound: 0x4000, upperBound: 0x5000)]
        let references = DataCrossReferenceResolver().resolve(
            instructions: rows, stringAddresses: [], selectorSlots: [0x4018], classSlots: [0x4010],
            dataRanges: ranges
        )
        XCTAssertEqual(references.map(\.kind), [XRefKind.classref, XRefKind.selref, XRefKind.data])
        // Without class slots the same load stays a data xref (older behaviour, unchanged API).
        let legacy = DataCrossReferenceResolver().resolve(
            instructions: rows, stringAddresses: [], selectorSlots: [0x4018], dataRanges: ranges
        )
        XCTAssertEqual(legacy.first?.kind, XRefKind.data)
    }

    func testLoaderProjectsClassReferenceSlots() {
        let projected = ObjCClassReferenceTarget.projection(of: [
            MachOObjectiveCReference(kind: "class", sourceAddress: 0x4010, targetAddress: 0x7000,
                                     sourceSection: "__DATA,__objc_classrefs", resolvedName: nil),
            MachOObjectiveCReference(kind: "class", sourceAddress: 0x4018, targetAddress: 0,
                                     sourceSection: "__DATA,__objc_classrefs", resolvedName: "NSString"),
            MachOObjectiveCReference(kind: "class", sourceAddress: 0x4020, targetAddress: 0,
                                     sourceSection: "__DATA,__objc_classrefs", resolvedName: ""),
        ])
        XCTAssertEqual(projected, [
            0x4010: ObjCClassReferenceTarget(name: nil, classAddress: 0x7000),
            0x4018: ObjCClassReferenceTarget(name: "NSString", classAddress: nil),
        ], "a slot with neither a target nor a name is dropped")
    }

    func testClassrefUsersMatchByAddressOrNameAndSelrefsMapToMethods() {
        var analysis = ImageAnalysis()
        analysis.objcClasses = [
            ObjCClass(name: "Local", superclassName: "NSObject", adoptedProtocols: [],
                      classMethods: [], instanceMethods: [
                          ObjCMethod(selector: "run", typeEncoding: "v16@0:8", isClassMethod: false, implementation: 0x9000),
                      ], ivars: [ObjCIvar(name: "_x", typeEncoding: "q")], properties: [], address: 0x7000),
        ]
        analysis.objcClassReferences = [
            0x4010: ObjCClassReferenceTarget(name: nil, classAddress: 0x7000), // stripped in-image ref
            0x4018: ObjCClassReferenceTarget(name: "Local", classAddress: nil),
            0x4020: ObjCClassReferenceTarget(name: "NSString", classAddress: nil),
        ]
        analysis.objcSelectors = [0x5000: "run"]
        analysis.xrefs = [
            XRef(id: UUID(), from: 0x1000, to: 0x4010, kind: XRefKind.classref),
            XRef(id: UUID(), from: 0x1100, to: 0x4018, kind: XRefKind.classref),
            XRef(id: UUID(), from: 0x1200, to: 0x4020, kind: XRefKind.classref),
            XRef(id: UUID(), from: 0x1300, to: 0x5000, kind: XRefKind.selref),
            XRef(id: UUID(), from: 0x1400, to: 0x4010, kind: XRefKind.data),
        ]
        XCTAssertNil(analysis.typeCatalog, "input changes clear the stored catalog")
        analysis.refreshTypeCatalog()
        let local = try? XCTUnwrap(analysis.typeCatalog?.entries.first { $0.name == "Local" })
        XCTAssertEqual(local?.users, [0x1000, 0x1100])
        XCTAssertEqual(local?.methods.first?.implementation, 0x9000)
        XCTAssertEqual(local?.methods.first?.selectorUsers, [0x1300])
        XCTAssertEqual(local?.members.first?.offset, nil)
        XCTAssertEqual(local?.members.first?.evidence, .unknown, "an ivar without an offset slot is unknown")
        analysis.xrefs.removeAll()
        XCTAssertNil(analysis.typeCatalog)
    }

    // MARK: - user types + accessor

    func testUserTypesKeepDWARFOffsetsAuthoredLayoutAndAppliedUsers() {
        let dwarf = TypeDefinition(kind: .struct, name: "dwarf_s", fields: [
            FieldDef(name: "a", type: "char", byteOffset: 0),
            FieldDef(name: "b", type: "int", byteOffset: 8), // a packed/aligned layout the ABI would not compute
        ])
        let authored = TypeDefinition(kind: .struct, name: "auth_s", fields: [
            FieldDef(name: "p", type: "void *"),
            FieldDef(name: "m", type: "mystery_t"),
            FieldDef(name: "q", type: "int"),
        ])
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "a", path: "/tmp/a", kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: ImageAnalysis()],
            addressOverrides: [
                ImageAddress(slot: .primary, address: 0x2000): AddressOverride(appliedTypeName: "auth_s"),
                ImageAddress(slot: ImageSlot(rawValue: 1), address: 0x3000): AddressOverride(appliedTypeName: "auth_s"),
            ],
            typeDefinitions: [dwarf, authored]
        )
        let catalog = snapshot.typeCatalog(in: .primary)
        let dwarfEntry = catalog.entries(named: "dwarf_s").first
        XCTAssertEqual(dwarfEntry?.members.map(\.offset), [0, 8])
        XCTAssertEqual(dwarfEntry?.members.map(\.evidence), [.descriptor, .descriptor])
        let authEntry = catalog.entries(named: "auth_s").first
        XCTAssertEqual(authEntry?.kind, .userType)
        XCTAssertEqual(authEntry?.evidence, .authored)
        XCTAssertEqual(authEntry?.users, [0x2000], "only this slot's applied addresses")
        XCTAssertEqual(authEntry?.members.map(\.evidence), [.authored, .authored, .unknown])
        XCTAssertEqual(authEntry?.members.first?.offset, 0)
        XCTAssertNil(authEntry?.members.last?.offset, "after an unresolvable member the layout is unknown")

        // FieldDef.byteOffset round-trips and is absent from older payloads.
        let encoded = try? JSONEncoder().encode(dwarf)
        XCTAssertEqual(try? JSONDecoder().decode(TypeDefinition.self, from: encoded ?? Data()), dwarf)
        let legacy = try? JSONDecoder().decode(FieldDef.self, from: Data(#"{"name":"a","type":"int"}"#.utf8))
        XCTAssertNil(legacy?.byteOffset)
        XCTAssertFalse(String(decoding: (try? JSONEncoder().encode(FieldDef(name: "a", type: "int"))) ?? Data(),
                              as: UTF8.self).contains("byteOffset"))

        XCTAssertTrue(snapshot.typeCatalog(in: ImageSlot(rawValue: 7)).entries.isEmpty, "unknown slot")
    }

    func testAuthoredPrefixSurvivesUnresolvableMiddleMember() throws {
        for kind: TypeKind in [.struct, .union] {
            let definition = TypeDefinition(kind: kind, name: "prefix", fields: [
                FieldDef(name: "tag", type: "char"),
                FieldDef(name: "count", type: "int"),
                FieldDef(name: "opaque", type: "mystery_t"),
                FieldDef(name: "tail", type: "double"),
                FieldDef(name: "other", type: "another_mystery_t"),
            ])
            let layout = definition.memberLayout()
            XCTAssertEqual(layout.map(\.field.name), ["tag", "count"])
            let entry = try XCTUnwrap(ImageTypeCatalogBuilder.userTypeEntries(
                typeDefinitions: [definition], addressOverrides: [:], slot: .primary
            ).first)
            XCTAssertEqual(entry.members.map(\.name), definition.fields.map(\.name))
            XCTAssertEqual(entry.members.map(\.offset), [0, kind == .struct ? 4 : 0, nil, nil, nil])
            XCTAssertEqual(entry.members.map(\.evidence), [.authored, .authored, .authored, .unknown, .unknown])
        }
    }

    func testAuthoredPrefixStoppingOnResolvableMemberKeepsSuffixUnknown() throws {
        for kind: TypeKind in [.struct, .union] {
            let definition = TypeDefinition(kind: kind, name: "unsupported", fields: [
                FieldDef(name: "head", type: "char"),
                FieldDef(name: "blocked", type: "int", layoutIsUnknown: true),
                FieldDef(name: "tail", type: "int"),
                FieldDef(name: "opaque", type: "mystery_t"),
            ])
            XCTAssertNotNil(TypeDefinition.size(ofType: definition.fields[1].type))
            XCTAssertEqual(definition.memberLayout().map(\.field.name), ["head"])
            let entry = try XCTUnwrap(ImageTypeCatalogBuilder.userTypeEntries(
                typeDefinitions: [definition], addressOverrides: [:], slot: .primary
            ).first)
            XCTAssertEqual(entry.members.map(\.offset), [0, nil, nil, nil])
            XCTAssertEqual(entry.members.map(\.evidence), [.authored, .unknown, .unknown, .unknown])
        }
    }

    func testOlderPayloadsWithoutNewFieldsDecode() throws {
        let legacyClass = #"{"name":"A","adoptedProtocols":[],"classMethods":[],"instanceMethods":[],"ivars":[{"name":"_x"}],"properties":[]}"#
        let cls = try JSONDecoder().decode(ObjCClass.self, from: Data(legacyClass.utf8))
        XCTAssertNil(cls.address)
        XCTAssertNil(cls.instanceSize)
        XCTAssertNil(cls.ivars.first?.offset)
        let legacySwift = #"{"kind":"struct","name":"S","fields":[]}"#
        XCTAssertNil(try JSONDecoder().decode(SwiftTypeDescriptor.self, from: Data(legacySwift.utf8)).descriptorAddress)

        // The worker payload carries the classref map and rebuilds the catalog on decode.
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "a", path: "/tmp/a", kind: "Mach-O", architecture: "arm64")],
            functions: [],
            instructions: [],
            xrefs: [XRef(id: UUID(), from: 0x1000, to: 0x4010, kind: XRefKind.classref)],
            hexBytes: Data(),
            objcClassReferences: [0x4010: ObjCClassReferenceTarget(name: "A", classAddress: 0x7000)],
            objcClasses: [cls],
            objcProtocols: [ObjCProtocol(name: "Independent", address: 0x8000, adoptedProtocols: [],
                                        requiredMethods: [], optionalMethods: [], properties: [])]
        )
        XCTAssertNotNil(snapshot.analysis(in: .primary)?.typeCatalog, "built once by the snapshot initializer")
        let payload = AnalysisPayloadCodec.payload(from: snapshot)
        let decoded = try JSONDecoder().decode(AnalysisResultPayload.self, from: JSONEncoder().encode(payload))
        XCTAssertEqual(decoded.objcClassReferences, payload.objcClassReferences)
        XCTAssertEqual(decoded.objcProtocols, payload.objcProtocols)
        var legacyPayload = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(payload)) as? [String: Any])
        legacyPayload.removeValue(forKey: "objcProtocols")
        let older = try JSONDecoder().decode(AnalysisResultPayload.self, from: JSONSerialization.data(withJSONObject: legacyPayload))
        XCTAssertTrue(older.objcProtocols.isEmpty)
        let restored = AnalysisPayloadCodec.snapshot(from: decoded)
        XCTAssertNotNil(restored.analysis(in: .primary)?.typeCatalog)
        XCTAssertEqual(restored.typeCatalog(in: .primary).entries(named: "Independent").first?.evidence, .descriptor)
        XCTAssertEqual(restored.typeCatalog(in: .primary).entries.first { $0.name == "A" }?.users, [0x1000])
    }

    // MARK: - list-image-types (scripting + MCP)

    private func makeStore() -> WorkspaceStore {
        let primaryOwner = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
        let siblingOwner = UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!
        var primary = ImageAnalysis()
        primary.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "P", fields: [SwiftField(name: "v", typeName: "Int")],
                                                  descriptorAddress: 0x8000)]
        var sibling = ImageAnalysis()
        sibling.objcClasses = [ObjCClass(name: "S", superclassName: "NSObject", adoptedProtocols: ["NSCopying"],
                                         classMethods: [], instanceMethods: [
                                             ObjCMethod(selector: "go", typeEncoding: nil, isClassMethod: false, implementation: 0x9100),
                                         ], ivars: [ObjCIvar(name: "_n", typeEncoding: "i", offset: 8, size: 4)],
                                         properties: [], address: 0x7100, instanceSize: 12)]
        let snapshot = WorkspaceSnapshot(
            binaries: [
                BinaryImage(id: primaryOwner, name: "p", path: "/tmp/p", kind: "Mach-O", architecture: "arm64", slot: .primary),
                BinaryImage(id: siblingOwner, name: "s", path: "/tmp/s", kind: "Mach-O", architecture: "arm64",
                            slot: ImageSlot(rawValue: 1)),
            ],
            analysisBySlot: [.primary: primary, ImageSlot(rawValue: 1): sibling]
        )
        return WorkspaceStore(workspaceName: "RX-02a", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    func testListImageTypesThroughScriptingAPI() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let primary = try api.execute("list-image-types")
        XCTAssertEqual(primary["imageSlot"], .int(0))
        XCTAssertEqual(primary["total"], .int(1))
        let point = try XCTUnwrap(primary["types"]?.arrayValue?.first)
        XCTAssertEqual(point["kind"]?.stringValue, "swiftStruct")
        XCTAssertEqual(point["id"]?["address"]?.stringValue, "0x8000")
        XCTAssertEqual(point["members"]?.arrayValue?.first?["offset"], .null)
        XCTAssertEqual(point["members"]?.arrayValue?.first?["evidence"]?.stringValue, "unknown")

        let sibling = try api.execute("list-image-types", arguments: .object(["image": .int(1), "kind": .string("objcClass")]))
        XCTAssertEqual(sibling["imageSlot"], .int(1))
        XCTAssertEqual(sibling["imageOwner"]?.stringValue, "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")
        let s = try XCTUnwrap(sibling["types"]?.arrayValue?.first)
        XCTAssertEqual(s["name"]?.stringValue, "S")
        XCTAssertEqual(s["id"]?["slot"], .int(1))
        XCTAssertEqual(s["id"]?["address"]?.stringValue, "0x7100")
        XCTAssertEqual(s["instanceSize"], .int(12))
        XCTAssertEqual(s["members"]?.arrayValue?.first?["offset"], .int(8))
        XCTAssertEqual(s["members"]?.arrayValue?.first?["evidence"]?.stringValue, "descriptor")
        XCTAssertEqual(s["methods"]?.arrayValue?.first?["implementation"]?.stringValue, "0x9100")

        let all = try api.execute("list-image-types", arguments: .object(["image": .int(1), "limit": .int(1)]))
        XCTAssertEqual(all["total"], .int(2), "the class and its name-only protocol")
        XCTAssertEqual(all["types"]?.arrayValue?.count, 1)
        XCTAssertThrowsError(try api.execute("list-image-types", arguments: .object(["kind": .string("bogus")])))
        XCTAssertThrowsError(try api.execute("list-image-types", arguments: .object(["image": .int(9)])))
    }

    func testListImageTypesThroughMCP() throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()))
        func request(_ method: String, _ params: ScriptValue? = nil) -> ScriptValue {
            var object: [String: ScriptValue] = ["jsonrpc": .string("2.0"), "id": .int(1), "method": .string(method)]
            if let params { object["params"] = params }
            return .object(object)
        }
        let tools = server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue ?? []
        let tool = try XCTUnwrap(tools.first { $0["name"]?.stringValue == "list-image-types" })
        XCTAssertNotNil(tool["inputSchema"]?["properties"]?["image"])
        XCTAssertEqual(tool["inputSchema"]?["properties"]?["kind"]?["enum"]?.arrayValue?.count, TypeAtlasKind.allCases.count)
        XCTAssertEqual(tool["annotations"]?["readOnlyHint"], .bool(true))

        let response = server.handle(request("tools/call", .object([
            "name": .string("list-image-types"), "arguments": .object(["image": .int(1)]),
        ])))
        XCTAssertEqual(response?["result"]?["isError"], .bool(false))
        let payload = try ScriptValue.decode(Data(try XCTUnwrap(
            response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue
        ).utf8))
        XCTAssertEqual(payload["imageSlot"], .int(1))
        XCTAssertEqual(payload["types"]?.arrayValue?.first?["name"]?.stringValue, "S")
        assertMCPToolArgumentError(server.handle(request("tools/call", .object([
            "name": .string("list-image-types"), "arguments": .object(["kind": .string("bogus")]),
        ]))), field: "kind", code: "malformedInput")
    }
}

// SW4 controls are synthetic, helper/model-only and authored but NOT CONFIRMED.
// They do not claim that catalog.name or list-image-types has been changed.
extension ImageTypeCatalogTests {
    private func sw4Record(
        _ source: SwiftMetadataMethod.Source = .vtable, index: UInt64 = 0,
        descriptor: UInt64 = 0x2000, implementation: UInt64? = 0x3000,
        flags: UInt32? = 0x10
    ) -> SwiftMetadataMethod {
        SwiftMetadataMethod(source: source, index: index, descriptorAddress: descriptor,
                            implementation: implementation, flags: flags)
    }

    private func sw4Links(_ methods: [SwiftMetadataMethod]) -> SwiftMetadataFunctionExtractor.MethodLinks {
        var links = SwiftMetadataFunctionExtractor.MethodLinks()
        links.types[0x1000] = methods
        return links
    }

    func testSW4SingleSymbolNamesTheSyntheticVtableSlotOnlyAtItsExactImplementation() throws {
        let input = sw4Record(index: 3)
        let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
            sw4Links([input]), symbols: [0x3000: ["one_symbol"], 0x2000: ["descriptor_symbol"]]
        )
        let record = try XCTUnwrap(result.types[0x1000]?.first)
        XCTAssertEqual(record.name, "one_symbol")
        XCTAssertEqual(record.implementationSymbol?.rawLinkageName, "one_symbol")
        XCTAssertEqual(record.label, "vtable #3 (name unknown)")
        var withoutPresentation = record
        withoutPresentation.implementationSymbol = nil
        XCTAssertEqual(withoutPresentation, input, "encoded slot facts must not change")
    }

    func testSW4NoSymbolAndNilImplementationKeepTheExactUnnamedText() throws {
        let inputs = [sw4Record(index: 7),
                      sw4Record(index: 8, descriptor: 0x2008, implementation: nil, flags: 0x40)]
        let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
            sw4Links(inputs), symbols: [0x2fff: ["nearby_symbol"], 0x2008: ["async_record_symbol"]]
        )
        let records = try XCTUnwrap(result.types[0x1000])
        XCTAssertEqual(records.map(\.name), ["vtable #7 (name unknown)", "vtable #8 (name unknown)"])
        XCTAssertTrue(records.allSatisfy { $0.implementationSymbol == nil })
        XCTAssertEqual(records, inputs)
    }

    func testSW4AliasesAndDuplicateSymbolRecordsNeverSelectTheFirstName() throws {
        for candidates in [["first", "second"], ["second", "first"], ["same", "same"], [], [""]] {
            let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
                sw4Links([sw4Record(index: 9)]), symbols: [0x3000: candidates]
            )
            let record = try XCTUnwrap(result.types[0x1000]?.first)
            XCTAssertNil(record.implementationSymbol)
            XCTAssertEqual(record.name, "vtable #9 (name unknown)")
        }
    }

    func testSW4SharedImplementationAcrossTypesAndWitnessesStaysUnnamed() throws {
        var links = sw4Links([sw4Record()])
        links.types[0x1100] = [sw4Record(.override, index: 1, descriptor: 0x2100)]
        links.conformances[0x1200] = [sw4Record(.witness, index: 2, descriptor: 0x2200)]
        let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(links, symbols: [0x3000: ["shared"]])
        XCTAssertEqual(try XCTUnwrap(result.types[0x1000]?.first).name, "vtable #0 (name unknown)")
        XCTAssertEqual(try XCTUnwrap(result.types[0x1100]?.first).name, "override #1 (name unknown)")
        XCTAssertEqual(try XCTUnwrap(result.conformances[0x1200]?.first).name, "witness #2 (name unknown)")
        XCTAssertEqual(result.types, links.types)
        XCTAssertEqual(result.conformances, links.conformances)
    }

    func testSW4UniqueOverrideAndWitnessUseTheSameExactSymbolRule() throws {
        var links = sw4Links([sw4Record(.override, implementation: 0x3100)])
        links.conformances[0x1200] = [sw4Record(.witness, descriptor: 0x2200, implementation: 0x3200)]
        let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
            links, symbols: [0x3100: ["override_symbol"], 0x3200: ["witness_symbol"]]
        )
        XCTAssertEqual(try XCTUnwrap(result.types[0x1000]?.first).name, "override_symbol")
        XCTAssertEqual(try XCTUnwrap(result.conformances[0x1200]?.first).name, "witness_symbol")
        XCTAssertEqual(try XCTUnwrap(result.types[0x1000]?.first).label, "override #0 (name unknown)")
        XCTAssertEqual(try XCTUnwrap(result.conformances[0x1200]?.first).label, "witness #0 (name unknown)")
    }

    func testSW4ExistingDemanglerDisplayAndExactRawSpellingAreBothRetained() throws {
        let raw = "_$s4Test3runyyF"
        let demangled = try XCTUnwrap(SwiftDemangler.demangle(raw))
        XCTAssertNotEqual(demangled, SwiftDemangler.tooComplexMarker)
        let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(sw4Links([sw4Record()]), symbols: [0x3000: [raw]])
        let record = try XCTUnwrap(result.types[0x1000]?.first)
        XCTAssertEqual(record.name, demangled)
        XCTAssertEqual(record.implementationSymbol?.rawLinkageName, raw)
    }

    func testSW4NilDemangleAndComplexityMarkerFallBackToTheExactRawSymbol() throws {
        let opaque = "opaque_linkage_symbol"
        XCTAssertNil(SwiftDemangler.demangle(opaque))
        let complex = "$s" + String(repeating: "a", count: SwiftDemangler.maxMangledLength)
        XCTAssertEqual(SwiftDemangler.demangle(complex), SwiftDemangler.tooComplexMarker)
        for raw in [opaque, complex] {
            let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(sw4Links([sw4Record()]), symbols: [0x3000: [raw]])
            let record = try XCTUnwrap(result.types[0x1000]?.first)
            XCTAssertEqual(record.name, raw)
            XCTAssertEqual(record.implementationSymbol?.rawLinkageName, raw)
            XCTAssertNotEqual(record.name, SwiftDemangler.tooComplexMarker)
        }
        let marker = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
            sw4Links([sw4Record()]), symbols: [0x3000: [SwiftDemangler.tooComplexMarker]]
        )
        XCTAssertNil(try XCTUnwrap(marker.types[0x1000]?.first).implementationSymbol)
    }

    func testSW4ImagesWithEqualAddressesNeverShareSymbolEvidence() throws {
        let links = sw4Links([sw4Record()])
        let first = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(links, symbols: [0x3000: ["image_one"]])
        let second = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(links, symbols: [0x3000: ["image_two"]])
        let absent = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(links, symbols: [:])
        XCTAssertEqual(try XCTUnwrap(first.types[0x1000]?.first).name, "image_one")
        XCTAssertEqual(try XCTUnwrap(second.types[0x1000]?.first).name, "image_two")
        XCTAssertNil(try XCTUnwrap(absent.types[0x1000]?.first).implementationSymbol)
        XCTAssertNil(try XCTUnwrap(links.types[0x1000]?.first).implementationSymbol)
    }

    func testSW4ReannotationClearsStaleEvidenceAndPreservesEmptyVersusAbsentTables() throws {
        var links = sw4Links([sw4Record()])
        links.types[0x1100] = []
        let named = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(links, symbols: [0x3000: ["symbol"]])
        let unnamed = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(named, symbols: [:])
        XCTAssertEqual(unnamed.types, links.types)
        XCTAssertEqual(unnamed.types[0x1100]?.count, 0)
        XCTAssertNil(unnamed.types[0x1200])
        var shared = named
        shared.conformances[0x1200] = [sw4Record(.witness, descriptor: 0x2200)]
        let result = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(shared, symbols: [0x3000: ["symbol"]])
        XCTAssertNil(try XCTUnwrap(result.types[0x1000]?.first).implementationSymbol)
        XCTAssertNil(try XCTUnwrap(result.conformances[0x1200]?.first).implementationSymbol)
    }

    func testSW4LegacyCodableRecordDefaultsToUnnamedAndNamedEvidenceRoundTrips() throws {
        let legacy = Data(#"{"source":"vtable","index":18446744073709551615,"descriptorAddress":8192,"implementation":12288,"flags":null}"#.utf8)
        let decoded = try JSONDecoder().decode(SwiftMetadataMethod.self, from: legacy)
        XCTAssertNil(decoded.implementationSymbol)
        XCTAssertEqual(decoded.name, "vtable #18446744073709551615 (name unknown)")
        XCTAssertNil(decoded.isInstance)
        let named = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(sw4Links([decoded]), symbols: [0x3000: ["symbol"]])
        let record = try XCTUnwrap(named.types[0x1000]?.first)
        let roundTrip = try JSONDecoder().decode(SwiftMetadataMethod.self, from: JSONEncoder().encode(record))
        XCTAssertEqual(roundTrip, record)
        XCTAssertEqual(roundTrip.label, "vtable #18446744073709551615 (name unknown)")
    }
}

/// Compiles tiny host fixtures (skipped when xcrun or the SDK is unavailable).
private enum HostFixture {
    static func objc(_ source: String) throws -> URL {
        let dir = try scratch("rx02a-objc")
        let file = dir.appendingPathComponent("t.m")
        try source.write(to: file, atomically: true, encoding: .utf8)
        let binary = dir.appendingPathComponent("t")
        try run(["clang", "-arch", "arm64", "-fobjc-arc", "-fno-objc-msgsend-selector-stubs",
                 "-framework", "Foundation", "-o", binary.path, file.path])
        return binary
    }

    static func swiftDylib(_ source: String) throws -> Data {
        let dir = try scratch("rx02a-swift")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("M.swift")
        try source.write(to: file, atomically: true, encoding: .utf8)
        let dylib = dir.appendingPathComponent("libM.dylib")
        try run(["swiftc", "-target", "arm64-apple-macos13", "-emit-library", "-o", dylib.path, file.path])
        return try Data(contentsOf: dylib)
    }

    private static func scratch(_ prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func run(_ arguments: [String]) throws {
        let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
        guard FileManager.default.isExecutableFile(atPath: xcrun.path) else { throw XCTSkip("xcrun unavailable") }
        let process = Process()
        process.executableURL = xcrun
        process.arguments = arguments
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = pipe
        try process.run()
        let drain = CoreTestPipeDrain(pipe)
        process.waitUntilExit()
        let output = drain.text()
        guard process.terminationStatus == 0 else {
            throw XCTSkip("\(arguments.first ?? "") failed (\(process.terminationStatus)): \(output)")
        }
    }
}

// SW4 B1: the catalog and list-image-types consume SwiftMetadataMethod.name (synthetic, no host fixture).
extension ImageTypeCatalogTests {
    private func sw4B1Analysis() -> ImageAnalysis {
        let named = SwiftMetadataMethod(source: .vtable, index: 0, descriptorAddress: 0x2000, implementation: 0x3000, flags: 0x10)
        let alias = SwiftMetadataMethod(source: .vtable, index: 1, descriptorAddress: 0x2008, implementation: 0x3100, flags: 0x10)
        let bare = SwiftMetadataMethod(source: .override, index: 2, descriptorAddress: 0x2010, implementation: 0x3200, flags: 0x10)
        var links = SwiftMetadataFunctionExtractor.MethodLinks()
        links.types[0x1000] = [named, alias, bare]
        let annotated = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
            links, symbols: [0x3000: ["one_symbol"], 0x3100: ["alias_a", "alias_b"]]
        )
        var analysis = ImageAnalysis()
        analysis.swiftTypes = [SwiftTypeDescriptor(kind: .class, name: "K", descriptorAddress: 0x1000,
                                                   methods: annotated.types[0x1000])]
        return analysis
    }

    func testSW4B1NamedSlotReachesCatalogRowAndAliasStaysUnnamed() throws {
        let catalog = ImageTypeCatalogBuilder.build(analysis: sw4B1Analysis())
        let row = try XCTUnwrap(catalog.entries(named: "K").first)
        XCTAssertEqual(row.methods.map(\.name), ["one_symbol", "vtable #1 (name unknown)", "override #2 (name unknown)"])
        XCTAssertEqual(row.methods.map(\.implementation), [0x3000, 0x3100, 0x3200])
        XCTAssertEqual(row.methods[0].swiftMetadata?.label, "vtable #0 (name unknown)")
    }

    func testSW4B1ListImageTypesReplyCarriesSymbolNameAndKeepsAliasUnnamed() throws {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "k", path: "/tmp/k", kind: "Mach-O", architecture: "arm64", slot: .primary)],
            analysisBySlot: [.primary: sw4B1Analysis()]
        )
        let store = WorkspaceStore(workspaceName: "SW4-B1", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
        let reply = try WorkspaceScriptingAPI(store: store).execute("list-image-types")
        let type = try XCTUnwrap(reply["types"]?.arrayValue?.first)
        let methods = try XCTUnwrap(type["methods"]?.arrayValue)
        XCTAssertEqual(methods.compactMap { $0["name"]?.stringValue },
                       ["one_symbol", "vtable #1 (name unknown)", "override #2 (name unknown)"])
        guard case let .object(fields) = methods[0] else { return XCTFail("method is not an object") }
        XCTAssertEqual(Set(fields.keys), ["name", "implementation", "isClassMethod", "selectorUsers", "swiftMetadata"])
    }
}
