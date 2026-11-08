import Foundation
import XCTest
@testable import MacScope

/// DC1 slice A (A1-A3): the export-trie parser retains re-export ordinal/name and resolver
/// offsets instead of discarding them, and the additive summary fields default to nil.
final class ExportTrieReexportRetentionTests: XCTestCase {
    // root(0): no terminal, children a->11, b->16, c->24
    // a(11): reexport ordinal 2, empty imported name (same spelling)
    // b(16): reexport ordinal 3, imported name "xyz"
    // c(24): stub-and-resolver, address 0x20, resolver offset 0x40
    private let trie: [UInt8] = [
        0, 3, 97, 0, 11, 98, 0, 16, 99, 0, 24,
        3, 0x08, 0x02, 0x00, 0,
        6, 0x08, 0x03, 120, 121, 122, 0, 0,
        3, 0x10, 0x20, 0x40, 0,
    ]

    private func parse() throws -> [MachOExport] {
        try MachOParser().parseExportTrie(
            in: Data([0] + trie), exportOffset: 1, exportSize: UInt32(trie.count),
            commandIndex: 1, source: "LC_DYLD_EXPORTS_TRIE", imageBase: 0x1_0000_0000
        )
    }

    func testA1ReexportOrdinalAndSameSpellingRetained() throws {
        let a = try XCTUnwrap(parse().first { $0.name == "a" })
        XCTAssertEqual(a.reexport, MachOExportReexport(ordinal: 2, importedName: nil))
        XCTAssertNil(a.address)
        XCTAssertNil(a.resolverOffset)
        XCTAssertEqual(a.flags, 0x08)
    }

    func testA2ReexportImportedNameRetained() throws {
        let b = try XCTUnwrap(parse().first { $0.name == "b" })
        XCTAssertEqual(b.reexport, MachOExportReexport(ordinal: 3, importedName: "xyz"))
        XCTAssertNil(b.address)
    }

    func testA3ResolverOffsetRetainedAndOrdinaryTerminalsUnchanged() throws {
        let exports = try parse()
        let c = try XCTUnwrap(exports.first { $0.name == "c" })
        XCTAssertEqual(c.resolverOffset, 0x40)
        XCTAssertEqual(c.address, 0x1_0000_0020)
        XCTAssertNil(c.reexport)
        XCTAssertEqual(exports.map(\.name), ["a", "b", "c"])

        // Ordinary terminals keep nil re-export/resolver data.
        let ordinary: [UInt8] = [0, 1, 97, 0, 5, 2, 0, 0x10, 0]
        let plain = try MachOParser().parseExportTrie(
            in: Data(ordinary), exportOffset: 0, exportSize: UInt32(ordinary.count),
            commandIndex: 1, source: "LC_DYLD_EXPORTS_TRIE", imageBase: 0
        )
        XCTAssertNil(plain.first?.reexport)
        XCTAssertNil(plain.first?.resolverOffset)
    }

    func testA2CompletenessReportedAndLegacyArrayUnchanged() throws {
        let parser = MachOParser()
        let complete = try parser.parseExportTrieReportingCompleteness(
            in: Data([0] + trie), exportOffset: 1, exportSize: UInt32(trie.count),
            commandIndex: 1, source: "LC_DYLD_EXPORTS_TRIE", imageBase: 0x1_0000_0000
        )
        XCTAssertTrue(complete.complete)
        XCTAssertEqual(complete.exports, try parse())

        // A terminal on the root has an empty name: it cannot be an export, and the walk says so.
        let rootTerminal: [UInt8] = [2, 0, 0x10, 0]
        let incomplete = try parser.parseExportTrieReportingCompleteness(
            in: Data(rootTerminal), exportOffset: 0, exportSize: UInt32(rootTerminal.count),
            commandIndex: 1, source: "LC_DYLD_EXPORTS_TRIE", imageBase: 0
        )
        XCTAssertFalse(incomplete.complete)
        XCTAssertTrue(incomplete.exports.isEmpty)
        let legacy = try parser.parseExportTrie(
            in: Data(rootTerminal), exportOffset: 0, exportSize: UInt32(rootTerminal.count),
            commandIndex: 1, source: "LC_DYLD_EXPORTS_TRIE", imageBase: 0
        )
        XCTAssertEqual(legacy, incomplete.exports)
    }

    func testSummaryFieldsDecodeFromLegacyJSON() throws {
        let importJSON = #"{"id":"00000000-0000-0000-0000-000000000001","name":"_x"}"#.data(using: .utf8)!
        let legacyImport = try JSONDecoder().decode(ImportSummary.self, from: importJSON)
        XCTAssertNil(legacyImport.origin)
        let exportJSON = #"{"id":"00000000-0000-0000-0000-000000000002","name":"_y","source":"s"}"#.data(using: .utf8)!
        let legacyExport = try JSONDecoder().decode(ExportSummary.self, from: exportJSON)
        XCTAssertNil(legacyExport.reexportOrdinal)
        XCTAssertNil(legacyExport.reexportImportedName)
        XCTAssertNil(legacyExport.resolverOffset)
    }
}
