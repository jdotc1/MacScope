import Foundation
import XCTest
@testable import MacScope

// Authored, unrun.
final class AnalysisTypeCatalogCanonicalizationTests: XCTestCase {
    func testPopulatedCatalogCanonicalizesStably() throws {
        let catalog = filledCatalog()
        let text = try AnalysisSnapshotCanonicalizer.canonicalDocument(catalog)
        XCTAssertEqual(text, try AnalysisSnapshotCanonicalizer.canonicalDocument(catalog))
        XCTAssertEqual(catalog, filledCatalog())
        XCTAssertEqual(text, try AnalysisSnapshotCanonicalizer.canonicalDocument(filledCatalog()))
        XCTAssertEqual(Set(catalog.entries.map(\.kind)), Set(TypeAtlasKind.allCases))
    }

    func testPopulatedCatalogHasNoInputUUIDs() throws {
        XCTAssertTrue(try AnalysisSnapshotCanonicalizer.inputUUIDs(in: filledCatalog()).isEmpty)
    }

    func testPopulatedCatalogFixtureIsComplete() {
        assertFilled(filledCatalog(), path: "catalog")
    }

    func testEveryCatalogFieldChangesCanonicalText() throws {
        try checkWritable(\ImageTypeCatalog.self, [
            edit("slot", \.slot, ImageSlot(rawValue: 9)), edit("entries", \.entries, [])])
        try checkWritable(\ImageTypeCatalog.entries[0].id, [
            edit("slot", \.slot, ImageSlot(rawValue: 9)), edit("kind", \.kind, .objcClass),
            edit("key", \.key, .name("changed"))])
        try checkWritable(\ImageTypeCatalog.entries[0], [
            edit("id", \.id, .init(slot: .primary, kind: .userType, key: .name("other"))),
            edit("kind", \.kind, .objcClass), edit("name", \.name, "other"),
            edit("superclass", \.superclass, "other"), edit("members", \.members, []),
            edit("conformances", \.conformances, []), edit("methods", \.methods, []),
            edit("users", \.users, []), edit("evidence", \.evidence, .unknown),
            edit("instanceSize", \.instanceSize, 65), edit("declaredProperties", \.declaredProperties, []),
            edit("swiftConformanceMethods", \.swiftConformanceMethods, []),
            edit("swiftMethodTableResolved", \.swiftMethodTableResolved, false),
            edit("imported", \.imported, nil), edit("qualifiedName", \.qualifiedName, "other"),
            edit("swiftSuperclass", \.swiftSuperclass, "other"), edit("isGeneric", \.isGeneric, false),
            edit("isPrivateOrLocal", \.isPrivateOrLocal, false),
            edit("isImportedCType", \.isImportedCType, false),
            edit("hasUnassignedSwiftConformanceRecords", \.hasUnassignedSwiftConformanceRecords, false)])
        try checkWritable(\ImageTypeCatalog.entries[0].members[0], [
            edit("name", \.name, "other"), edit("type", \.type, "other"), edit("offset", \.offset, 9),
            edit("evidence", \.evidence, .unknown), edit("size", \.size, 9), edit("imported", \.imported, nil)])
        try checkWritable(\ImageTypeCatalog.entries[0].methods[0], [
            edit("name", \.name, "other"), edit("implementation", \.implementation, 513),
            edit("isClassMethod", \.isClassMethod, false), edit("selectorUsers", \.selectorUsers, []),
            edit("category", \.category, "other"), edit("isOptionalRequirement", \.isOptionalRequirement, false),
            edit("swiftMetadata", \.swiftMetadata, nil)])
        try checkWritable(\ImageTypeCatalog.entries[0].swiftConformanceMethods![0], [
            edit("protocolName", \.protocolName, "other"), edit("descriptorAddress", \.descriptorAddress, 769),
            edit("methods", \.methods, [])])
        try checkWritable(\ImageTypeCatalog.entries[0].declaredProperties![0], [
            edit("name", \.name, "other"), edit("attributes", \.attributes, "other")])
        try checkWritable(\ImageTypeCatalog.entries[0].methods[0].swiftMetadata!, [
            edit("source", \.source, .witness), edit("index", \.index, 2),
            edit("descriptorAddress", \.descriptorAddress, 257), edit("implementation", \.implementation, 513),
            edit("flags", \.flags, 17), edit("implementationSymbol", \.implementationSymbol, nil)])
        try checkWritable(\ImageTypeCatalog.entries[0].methods[0].swiftMetadata!.implementationSymbol!, [
            edit("rawLinkageName", \.rawLinkageName, "other"), edit("name", \.name, "other")])
        try checkReplacements(ImageSlot(rawValue: 7), [("rawValue", ImageSlot(rawValue: 9))]) {
            var c = self.filledCatalog(); c.slot = $0; return c
        }
        try checkReplacements(importIdentity(), [
            ("archiveSHA256", importIdentity(archive: "archive-b")),
            ("declarationID", importIdentity(declaration: "decl-b"))]) {
            var c = self.filledCatalog(); c.entries[0].imported = self.importLayout(identity: $0); return c
        }
        try checkReplacements(importMember(), [
            ("fieldID", importMember(field: "field-b")), ("typeIdentity", importMember(identity: importIdentity(declaration: "decl-b"))),
            ("absoluteBitOffset", importMember(offset: 65)), ("bitWidth", importMember(width: 4)),
            ("flexibleArray", importMember(flexible: false)), ("anonymous", importMember(anonymous: false))]) {
            var c = self.filledCatalog(); c.entries[0].members[0].imported = $0; return c
        }
        try checkReplacements(importLayout(), [
            ("identity", importLayout(identity: importIdentity(declaration: "decl-b"))),
            ("configurationID", importLayout(configuration: "other")), ("targetTriple", importLayout(target: "other")),
            ("sdkIdentity", importLayout(sdk: "other")), ("compiler", importLayout(compiler: "other")),
            ("compilerVersion", importLayout(compilerVersion: "other")), ("libclangVersion", importLayout(clang: "other")),
            ("language", importLayout(language: "other")), ("extractorVersion", importLayout(extractor: "other")),
            ("input", importLayout(input: "other")), ("sourceHeader", importLayout(header: "other")),
            ("sourceLine", importLayout(line: 3)), ("sourceColumn", importLayout(column: 4)),
            ("typeKind", importLayout(type: "other")), ("recordKind", importLayout(record: "other")),
            ("layoutStatus", importLayout(status: "other")), ("layoutReason", importLayout(reason: "other")),
            ("alignmentBytes", importLayout(alignment: 16))]) {
            var c = self.filledCatalog(); c.entries[0].imported = $0; return c
        }
        let keyPairs: [(TypeAtlasEntryID.Key, TypeAtlasEntryID.Key)] = [(.address(5), .address(6)), (.name("5"), .name("6"))]
        for (a, b) in keyPairs {
            let payloads = Array(Mirror(reflecting: a).children)
            XCTAssertEqual(payloads.count, 1)
            let payload = try XCTUnwrap(payloads.first)
            switch a {
            case .address: XCTAssertEqual(payload.label, "address"); XCTAssertTrue(payload.value is UInt64)
            case .name: XCTAssertEqual(payload.label, "name"); XCTAssertTrue(payload.value is String)
            }
            var c = filledCatalog(); c.entries[0].id.key = a
            var d = c; d.entries[0].id.key = b
            XCTAssertNotEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(c),
                              try AnalysisSnapshotCanonicalizer.canonicalDocument(d))
        }
    }

    func testAddressAndNameKeysDiffer() throws {
        var a = filledCatalog(); a.entries[0].id.key = .address(5)
        var b = a; b.entries[0].id.key = .name("5")
        XCTAssertNotEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(a),
                          try AnalysisSnapshotCanonicalizer.canonicalDocument(b))
    }

    func testImageAnalysisCatalogIsSemantic() throws {
        var analysis = imageRows()
        let ids = try AnalysisSnapshotCanonicalizer.inputUUIDs(in: analysis)
        let absent = try AnalysisSnapshotCanonicalizer.canonicalImage(analysis, inputUUIDs: ids)
        analysis.refreshTypeCatalog()
        let catalog = try XCTUnwrap(analysis.typeCatalog)
        XCTAssertEqual(catalog.entries.count, 2)
        XCTAssertNotEqual(absent, try AnalysisSnapshotCanonicalizer.canonicalImage(analysis, inputUUIDs: ids))
        var changedClasses = analysis.objcClasses; changedClasses[0].name = "Replaced"
        analysis.objcClasses = changedClasses
        XCTAssertNil(analysis.typeCatalog)
        analysis.refreshTypeCatalog()
        var fresh = imageRows(objcName: "Replaced"); fresh.refreshTypeCatalog()
        XCTAssertEqual(analysis.typeCatalog, ImageTypeCatalogBuilder.build(analysis: analysis))
        XCTAssertEqual(try AnalysisSnapshotCanonicalizer.canonicalImage(analysis, inputUUIDs: ids),
                       try AnalysisSnapshotCanonicalizer.canonicalImage(fresh, inputUUIDs: ids))
        let current = try XCTUnwrap(analysis.typeCatalog)
        var moved = analysis; moved.typeCatalog = current.restamped(to: ImageSlot(rawValue: 9))
        XCTAssertNotEqual(try AnalysisSnapshotCanonicalizer.canonicalImage(analysis, inputUUIDs: ids),
                          try AnalysisSnapshotCanonicalizer.canonicalImage(moved, inputUUIDs: ids))
    }

    func testRehydratedCatalogEqualsFreshBuild() throws {
        let bytes = Data()
        var persisted = ImageAnalysis(); persisted.typeCatalog = .empty(in: ImageSlot(rawValue: 7))
        let request = try XCTUnwrap(UUID(uuidString: "12990000-0000-4000-8000-000000000001"))
        var loader = RehydrationLoaderProducts(requestID: request, requestedSliceIndex: nil,
            imageByteCount: bytes.count, sliceOffset: 0, sliceSize: 0, sections: [],
            mappings: FileAddressMapping.verifiedMappings(from: [], payloadLength: bytes.count))
        let rows = imageRows(); loader.objcClasses = rows.objcClasses; loader.swiftTypes = rows.swiftTypes
        let ids = try AnalysisSnapshotCanonicalizer.inputUUIDs(in: (persisted, loader))
        XCTAssertTrue(ids.contains(request))
        let rebuilt = try RehydrationDerivedProducts.rebuild(persisted: persisted, loader: loader,
            imageBytes: bytes, cancellation: .never)
        XCTAssertEqual(rebuilt.objcClasses, loader.objcClasses); XCTAssertEqual(rebuilt.swiftTypes, loader.swiftTypes)
        let catalog = try XCTUnwrap(rebuilt.typeCatalog)
        XCTAssertEqual(catalog.entries.count, 2)
        XCTAssertEqual(catalog, ImageTypeCatalogBuilder.build(analysis: rebuilt))
        XCTAssertEqual(try AnalysisSnapshotCanonicalizer.canonicalDocument(catalog, inputUUIDs: ids),
                       try AnalysisSnapshotCanonicalizer.canonicalDocument(ImageTypeCatalogBuilder.build(analysis: rebuilt), inputUUIDs: ids))
        var expected = rebuilt; expected.typeCatalog = ImageTypeCatalogBuilder.build(analysis: rebuilt)
        XCTAssertEqual(try AnalysisSnapshotCanonicalizer.canonicalImage(rebuilt, inputUUIDs: ids),
                       try AnalysisSnapshotCanonicalizer.canonicalImage(expected, inputUUIDs: ids))
    }

    private struct FieldEdit<T> {
        let name: String
        let key: PartialKeyPath<T>
        let change: (inout T) -> Void
    }
    private func edit<T, V>(_ name: String, _ key: WritableKeyPath<T, V>, _ value: V) -> FieldEdit<T> {
        FieldEdit(name: name, key: key, change: { $0[keyPath: key] = value })
    }
    private func checkWritable<T>(_ path: WritableKeyPath<ImageTypeCatalog, T>, _ edits: [FieldEdit<T>]) throws {
        let base = filledCatalog()[keyPath: path]
        XCTAssertEqual(Set(edits.map(\.key)).count, edits.count, "duplicate key path")
        let variants = edits.map { edit -> (String, T) in
            var value = base; edit.change(&value); return (edit.name, value)
        }
        try checkReplacements(base, variants) { value in
            var catalog = self.filledCatalog(); catalog[keyPath: path] = value; return catalog
        }
    }
    private func checkReplacements<T>(_ base: T, _ variants: [(String, T)],
                                      embed: (T) -> ImageTypeCatalog) throws {
        let fields = Array(Mirror(reflecting: base).children)
        XCTAssertEqual(variants.count, fields.count, "field count for \(T.self)")
        XCTAssertEqual(Set(variants.map { $0.0 }), Set(fields.compactMap(\.label)), "fields of \(T.self)")
        let original = try AnalysisSnapshotCanonicalizer.canonicalDocument(embed(base))
        for (name, changed) in variants {
            XCTAssertNotEqual(original, try AnalysisSnapshotCanonicalizer.canonicalDocument(embed(changed)), "\(T.self).\(name)")
        }
    }
    private func assertFilled(_ value: Any, path: String) {
        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .optional || mirror.displayStyle == .collection {
            XCTAssertFalse(mirror.children.isEmpty, "unexercised \(path)")
        }
        for (index, child) in mirror.children.enumerated() {
            assertFilled(child.value, path: path + "." + (child.label ?? String(index)))
        }
    }
    private func importIdentity(archive: String = "archive-a", declaration: String = "decl-a") -> ImportedTypeIdentity {
        .init(archiveSHA256: archive, declarationID: declaration)
    }
    private func importMember(field: String = "field-a", identity: ImportedTypeIdentity? = nil,
                              offset: UInt64 = 64, width: UInt64 = 3, flexible: Bool = true,
                              anonymous: Bool = true) -> ImportedTypeMemberMetadata {
        .init(fieldID: field, typeIdentity: identity ?? importIdentity(), absoluteBitOffset: offset,
              bitWidth: width, flexibleArray: flexible, anonymous: anonymous)
    }
    private func importLayout(identity: ImportedTypeIdentity? = nil, configuration: String = "config",
                              target: String = "arm64-apple-macos", sdk: String = "sdk", compiler: String = "clang",
                              compilerVersion: String = "1", clang: String = "2", language: String = "c",
                              extractor: String = "3", input: String = "input", header: String = "header.h",
                              line: UInt32 = 2, column: UInt32 = 3, type: String = "record", record: String = "struct",
                              status: String = "complete", reason: String = "recorded", alignment: UInt64 = 8) -> ImportedTypeLayoutMetadata {
        .init(identity: identity ?? importIdentity(), configurationID: configuration, targetTriple: target,
              sdkIdentity: sdk, compiler: compiler, compilerVersion: compilerVersion, libclangVersion: clang,
              language: language, extractorVersion: extractor, input: input, sourceHeader: header,
              sourceLine: line, sourceColumn: column, typeKind: type, recordKind: record,
              layoutStatus: status, layoutReason: reason, alignmentBytes: alignment)
    }
    private func tableMethod() -> SwiftMetadataMethod {
        .init(source: .vtable, index: 1, descriptorAddress: 256, implementation: 512, flags: 16,
              implementationSymbol: .init(rawLinkageName: "_$sMethod", name: "method"))
    }
    private func filledCatalog() -> ImageTypeCatalog {
        let slot = ImageSlot(rawValue: 7)
        let member = TypeAtlasMember(name: "member", type: "Int", offset: 8, evidence: .compilerImport,
                                    size: 8, imported: importMember())
        let method = TypeAtlasMethod(name: "method", implementation: 512, isClassMethod: true,
            selectorUsers: [1024], category: "Category", isOptionalRequirement: true, swiftMetadata: tableMethod())
        let entries = TypeAtlasKind.allCases.enumerated().map { index, kind in
            TypeAtlasEntry(id: .init(slot: slot, kind: kind, key: index == 0 ? .address(5) : .name("5")),
                kind: kind, name: kind.rawValue, superclass: "Base", members: [member], conformances: ["P"],
                methods: [method], users: [1024], evidence: .descriptor, instanceSize: 64,
                declaredProperties: [.init(name: "property", attributes: "Ti,N")],
                swiftConformanceMethods: [.init(protocolName: "P", descriptorAddress: 768, methods: [method])],
                swiftMethodTableResolved: true, imported: importLayout(), qualifiedName: "Module.Type",
                swiftSuperclass: "BaseMangled", isGeneric: true, isPrivateOrLocal: true,
                isImportedCType: true, hasUnassignedSwiftConformanceRecords: true)
        }
        return ImageTypeCatalog(slot: slot, entries: entries)
    }
    private func imageRows(objcName: String = "ObjC") -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.objcClasses = [.init(name: objcName, superclassName: nil, adoptedProtocols: [], classMethods: [],
            instanceMethods: [.init(selector: "method", typeEncoding: "v@:", isClassMethod: false, implementation: 512)],
            ivars: [.init(name: "member", typeEncoding: "i", offset: 8, size: 4)], properties: [], address: 256, instanceSize: 16)]
        analysis.swiftTypes = [.init(kind: .class, name: "Swift", fields: [.init(name: "field", typeName: "Int", byteOffset: 8)],
            descriptorAddress: 768, methods: [tableMethod()], qualifiedName: "Module.Swift")]
        return analysis
    }
}
