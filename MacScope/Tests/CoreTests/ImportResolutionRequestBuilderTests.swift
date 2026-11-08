import Foundation
import XCTest
@testable import MacScope

/// DC1 slice A (A8): typed pre-lookup misses and request construction over crafted metadata.
final class ImportResolutionRequestBuilderTests: XCTestCase {
    private func dylib(_ ordinal: Int, _ path: String, kind: String = "required") -> MachOLoadMetadata.DependentDylib {
        .init(path: path, kind: kind, currentVersion: "1.0.0", compatibilityVersion: "1.0.0", ordinal: ordinal)
    }

    private func symbol(_ name: String, _ origins: [ImportOrigin]) -> MachOLoadMetadata.ImportedSymbol {
        .init(name: name, libraryOrdinal: nil, libraryName: nil, isWeak: false, addend: nil,
              source: "test", origins: origins)
    }

    private func metadata(_ symbols: [MachOLoadMetadata.ImportedSymbol],
                          dylibs: [MachOLoadMetadata.DependentDylib]) -> MachOLoadMetadata {
        MachOLoadMetadata(codeSignature: nil, importedSymbols: symbols, dependentDylibs: dylibs)
    }

    private func nlist(_ raw: Int, weak: Bool = false, tableIndex: Int = 0) -> ImportOrigin {
        ImportOrigin(encoding: .nlistDesc, rawOrdinal: raw, isWeak: weak, tableIndex: tableIndex)
    }

    private func chained(_ raw: Int, weak: Bool = false, tableIndex: Int = 0) -> ImportOrigin {
        ImportOrigin(encoding: .chainedFixup, rawOrdinal: raw, isWeak: weak, tableIndex: tableIndex)
    }

    private func miss(_ entry: ImportResolutionEntry) -> ImportResolutionPreLookupMiss? {
        if case .miss(let value) = entry.outcome { return value }
        return nil
    }

    func testA8SpecialAndUnknownOrdinalsAreTypedMisses() {
        let dylibs = [dylib(1, "/usr/lib/libSystem.B.dylib")]
        let entries = ImportResolutionRequestBuilder.build(from: metadata([
            symbol("legacy", []),
            symbol("nlistSelf", [nlist(0)]),
            symbol("nlistFlat", [nlist(0xfe)]),
            symbol("nlistMain", [nlist(0xff)]),
            symbol("chainedSelf", [chained(0)]),
            symbol("chainedMain", [chained(-1)]),
            symbol("chainedFlat", [chained(-2)]),
            symbol("chainedWeak", [chained(-3)]),
            symbol("chainedUnknown", [chained(-4)]),
            symbol("outOfRange", [nlist(2)]),
            symbol("", [nlist(1)]),
        ], dylibs: dylibs))
        XCTAssertEqual(entries.map(miss), [
            .noOriginRecorded, .selfImage, .flatLookup, .mainExecutable, .selfImage, .mainExecutable,
            .flatLookup, .weakLookup, .unknownOrdinal(raw: -4),
            .ordinalOutOfRange(ordinal: 2, dependencyCount: 1), .emptySymbolName,
        ])
        XCTAssertNil(entries[0].origin)
    }

    func testA8PathVariablesAndRelativeInstallNamesAreMisses() {
        let dylibs = [
            dylib(1, "@rpath/libA.dylib"), dylib(2, "@loader_path/../libB.dylib"),
            dylib(3, "@executable_path/libC.dylib"), dylib(4, "libD.dylib"),
        ]
        let entries = ImportResolutionRequestBuilder.build(from: metadata(
            (1...4).map { symbol("s\($0)", [nlist($0)]) }, dylibs: dylibs))
        XCTAssertEqual(entries.map(miss), [
            .unresolvedPathVariable(installName: "@rpath/libA.dylib"),
            .unresolvedPathVariable(installName: "@loader_path/../libB.dylib"),
            .unresolvedPathVariable(installName: "@executable_path/libC.dylib"),
            .nonAbsoluteInstallName(installName: "libD.dylib"),
        ])
    }

    func testA8Chained254And255AreDependenciesNotSpecials() {
        var dylibs: [MachOLoadMetadata.DependentDylib] = []
        for ordinal in 1...255 { dylibs.append(dylib(ordinal, "/usr/lib/lib\(ordinal).dylib")) }
        let entries = ImportResolutionRequestBuilder.build(from: metadata([
            symbol("a", [chained(254)]), symbol("b", [chained(255)]),
            symbol("c", [nlist(0xfe)]), symbol("d", [nlist(0xff)]),
        ], dylibs: dylibs))
        guard case .request(let a) = entries[0].outcome, case .request(let b) = entries[1].outcome else {
            return XCTFail("chained 254/255 must resolve to dependencies")
        }
        XCTAssertEqual(a.installName, "/usr/lib/lib254.dylib")
        XCTAssertEqual(b.installName, "/usr/lib/lib255.dylib")
        XCTAssertEqual(miss(entries[2]), .flatLookup)
        XCTAssertEqual(miss(entries[3]), .mainExecutable)
    }

    func testA8OneRequestPerDistinctOriginInInputOrderWithoutCollapsingNames() {
        let dylibs = [dylib(1, "/usr/lib/libSystem.B.dylib", kind: "required"),
                      dylib(2, "/usr/lib/libz.1.dylib", kind: "weak")]
        let entries = ImportResolutionRequestBuilder.build(from: metadata([
            symbol("dup", [chained(1), nlist(1, weak: true), chained(1), nlist(1, weak: true, tableIndex: 7)]),
            symbol("dup", [nlist(2)]),
            symbol("other", [chained(2, weak: true)]),
        ], dylibs: dylibs))
        XCTAssertEqual(entries.map(\.symbolName), ["dup", "dup", "dup", "dup", "other"])
        let requests = entries.compactMap { entry -> ImportResolutionRequest? in
            if case .request(let request) = entry.outcome { return request }
            return nil
        }
        XCTAssertEqual(requests.count, 5)
        XCTAssertEqual(requests.map(\.dependencyOrdinal), [1, 1, 1, 2, 2])
        XCTAssertEqual(requests.map(\.origin.tableIndex), [0, 0, 7, 0, 0])
        XCTAssertEqual(requests.map(\.isWeakImport), [false, true, true, false, true])
        XCTAssertEqual(requests[3].dependencyKind, "weak")
        XCTAssertEqual(requests[0].installName, "/usr/lib/libSystem.B.dylib")
        XCTAssertEqual(requests[4].installName, "/usr/lib/libz.1.dylib")
    }
}
