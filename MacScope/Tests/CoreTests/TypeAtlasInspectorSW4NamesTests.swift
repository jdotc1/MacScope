import Foundation
import XCTest
@testable import MacScope

/// SW4 B2: the Type Atlas inspector names Swift table slots from `SwiftMetadataMethod.name`, the
/// same field and decider the catalog uses; it has no symbol lookup of its own. Synthetic, no
/// host fixtures.
@MainActor
final class TypeAtlasInspectorSW4NamesTests: XCTestCase {
    private func catalogEntry() throws -> TypeAtlasEntry {
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
        return try XCTUnwrap(ImageTypeCatalogBuilder.build(analysis: analysis).entries(named: "K").first)
    }

    func testSymbolNamedSlotShowsTheSW4NameAndKeepsItsPosition() throws {
        let row = TypeAtlasInspectorReading(try catalogEntry()).methods[0]
        XCTAssertEqual(row.signature, "one_symbol")
        XCTAssertEqual(row.badge, "vtable #0")
        XCTAssertEqual(row.implementation, 0x3000)
    }

    func testSlotsWithoutAUniqueSymbolShowUnnamedNeverAGuess() throws {
        let rows = TypeAtlasInspectorReading(try catalogEntry()).methods
        XCTAssertEqual(rows.map(\.signature)[1...], ["vtable #1 (name unknown)", "override #2 (name unknown)"])
        XCTAssertEqual(rows.map(\.badge)[1...], ["vtable", "override"])
    }

    func testInspectorAndCatalogAgreeForEverySlot() throws {
        let entry = try catalogEntry()
        let reading = TypeAtlasInspectorReading(entry)
        XCTAssertEqual(reading.methods.map(\.signature), entry.methods.map(\.name))
        XCTAssertEqual(reading.methods.map(\.signature), entry.methods.map { $0.swiftMetadata?.name })
    }

    func testSymbolsAreNotTheInspectorsToLookUpOnlyUserNamesAreTaken() throws {
        // The reading takes no symbol table: a user name at an alias slot's address is the only
        // thing that changes it; an unrelated address changes nothing.
        let entry = try catalogEntry()
        XCTAssertEqual(TypeAtlasInspectorReading(entry, userNames: [0x9999: "x"]), TypeAtlasInspectorReading(entry))
    }

    func testUserRenameKeepsTheExistingDisplayAndReplacesTheSlotName() throws {
        // The catalog (ImageTypeCatalog.swift:327) has no user-rename rule, so the inspector's
        // existing display stays: the user's text replaces the slot name, the badge keeps position.
        let entry = try catalogEntry()
        let rows = TypeAtlasInspectorReading(entry, userNames: [0x3000: "myStart", 0x3100: "myAlias"]).methods
        XCTAssertEqual(rows.map(\.signature), ["myStart", "myAlias", "override #2 (name unknown)"])
        XCTAssertEqual(rows.map(\.badge), ["vtable #0", "vtable #1", "override"])
        XCTAssertEqual(entry.methods.map(\.name), ["one_symbol", "vtable #1 (name unknown)", "override #2 (name unknown)"],
                       "a rename never reaches the catalog's names")
    }
}
