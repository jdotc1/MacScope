import Foundation
import XCTest
@testable import MacScope

/// E4 slice A: callee identity comes from the unsymbolized `bl` target address, the loader's
/// indirect-symbol table and the Tier 1 allowlist, never from rendered name text.
final class ARCFoldIdentityTests: XCTestCase {
    private let callerStart: UInt64 = 0x1000
    private let stubAddress: UInt64 = 0x2100

    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: "00 00 00 94", mnemonic: mnemonic,
                       operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func stub(_ name: String? = "_objc_release", address: UInt64? = nil,
                      section: String = "__TEXT,__stubs",
                      kind: String = MachOIndirectSymbolKind.symbolStub.rawValue,
                      library: String? = "/usr/lib/libobjc.A.dylib", local: Bool = false,
                      absolute: Bool = false, size: UInt32 = 12) -> IndirectSymbolSummary {
        IndirectSymbolSummary(id: UUID(), kind: kind, sourceSection: section,
            address: address ?? stubAddress, entrySize: size, tableIndex: 0, rawSymbolIndex: 0,
            symbolIndex: 0, symbolName: name, libraryOrdinal: nil, libraryName: library,
            isLocal: local, isAbsolute: absolute)
    }

    private struct Fixture {
        var snapshot: WorkspaceSnapshot
        var target: (function: FunctionSummary, instructions: [InstructionRow])
        var analysis: ImageAnalysis
    }

    private func fixture(callTargets: [UInt64], indirectSymbols: [IndirectSymbolSummary],
                         extras: [FunctionSummary] = [],
                         overrides: [UInt64: AddressOverride] = [:]) -> Fixture {
        var rows: [InstructionRow] = []
        for (offset, target) in callTargets.enumerated() {
            rows.append(row(callerStart + UInt64(offset) * 4, "bl", "0x" + String(target, radix: 16)))
        }
        rows.append(row(callerStart + UInt64(callTargets.count) * 4, "ret", ""))
        let caller = FunctionSummary(id: UUID(), name: "_caller", startAddress: callerStart,
            endAddress: callerStart + UInt64(rows.count) * 4, confidence: 1)
        var analysis = ImageAnalysis()
        analysis.functions = [caller] + extras
        analysis.instructions = rows
        analysis.indirectSymbols = indirectSymbols
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "fixture", path: "/fixture/arc-fold",
            kind: "executable", architecture: "arm64", slot: .primary), analysis: analysis)
        for (address, override) in overrides { snapshot.addressOverrides[.primary(address)] = override }
        return Fixture(snapshot: snapshot, target: (caller, rows), analysis: analysis)
    }

    private func sites(_ fixture: Fixture) -> [UInt64: ARCCalleeIdentity] {
        fixture.snapshot.arcFoldCallSites(for: fixture.target, in: .primary)
    }

    // SPEC-3
    func testStubIdentityClassifiesByAddressNotText() {
        // Row 0x1000 calls the import stub; row 0x1004 calls a local function that is merely
        // named objc_release. Only the import-stub site is classified.
        let local = FunctionSummary(id: UUID(), name: "_objc_release", startAddress: 0x3000,
                                    endAddress: 0x3010, confidence: 1)
        let value = fixture(callTargets: [stubAddress, 0x3000], indirectSymbols: [stub()], extras: [local])
        let found = sites(value)
        XCTAssertEqual(Set(found.keys), [callerStart])
        XCTAssertEqual(found[callerStart]?.importSymbol, "objc_release")
        XCTAssertEqual(found[callerStart]?.family, .objc)
        XCTAssertEqual(found[callerStart]?.role, .release)
        XCTAssertNil(found[callerStart + 4])
    }

    // SPEC-4
    func testRenamedImportStillClassified() {
        let local = FunctionSummary(id: UUID(), name: "helper", startAddress: 0x3000,
                                    endAddress: 0x3010, confidence: 1)
        let renames: [UInt64: AddressOverride] = [
            stubAddress: AddressOverride(customName: "totally_unrelated_name"),
            0x3000: AddressOverride(customName: "objc_release"),
        ]
        let value = fixture(callTargets: [stubAddress, 0x3000], indirectSymbols: [stub()],
                            extras: [local], overrides: renames)
        let found = sites(value)
        XCTAssertEqual(Set(found.keys), [callerStart])
        XCTAssertEqual(found[callerStart]?.importSymbol, "objc_release")
    }

    // SPEC-5
    func testNonStubOrDuplicateSymbolNotClassified() {
        // Two rows at one address.
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(), stub("_objc_retain")])).isEmpty, "two rows at one address")
        // The same symbol name on two different stub addresses.
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(), stub(address: 0x2200)])).isEmpty, "duplicate symbol name")
        // A function range covers the stub address.
        let covering = FunctionSummary(id: UUID(), name: "covering", startAddress: 0x2000,
                                       endAddress: 0x2200, confidence: 1)
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress], indirectSymbols: [stub()],
            extras: [covering])).isEmpty, "function range covers the stub")
        // A function starts at the stub address.
        let atStub = FunctionSummary(id: UUID(), name: "atStub", startAddress: stubAddress,
                                     endAddress: stubAddress, confidence: 1)
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress], indirectSymbols: [stub()],
            extras: [atStub])).isEmpty, "function starts at the stub")
        // Pointer slots, local and absolute rows, wrong declared kind, empty name, zero size.
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(section: "__DATA,__la_symbol_ptr")])).isEmpty, "data pointer slot")
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(local: true)])).isEmpty, "local row")
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(absolute: true)])).isEmpty, "absolute row")
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(kind: MachOIndirectSymbolKind.lazySymbolPointer.rawValue)])).isEmpty,
            "kind contradicts section")
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(nil)])).isEmpty, "no symbol name")
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(size: 0)])).isEmpty, "zero entry size")
        // Overlapping neighbouring rows.
        XCTAssertTrue(sites(fixture(callTargets: [stubAddress],
            indirectSymbols: [stub(), stub("_objc_retain", address: stubAddress + 4)])).isEmpty,
            "overlapping rows")
        // Control: the clean fixture is classified.
        XCTAssertEqual(sites(fixture(callTargets: [stubAddress], indirectSymbols: [stub()])).count, 1)
    }

    func testUncataloguedAndNonARCImportsAreNotClassified() {
        for name in ["_malloc", "_free", "_objc_msgSend", "_mscope_uncatalogued_stub"] {
            let found = sites(fixture(callTargets: [stubAddress], indirectSymbols: [stub(name)]))
            XCTAssertTrue(found.isEmpty, name)
        }
    }

    func testTierOneCatalogMembersResolveWithRoleAndFamily() {
        let expectations: [(String, ARCFamily, ARCRole, Bool)] = [
            ("_objc_retain", .objc, .retain, false),
            ("_objc_release", .objc, .release, false),
            ("_objc_autorelease", .objc, .autorelease, false),
            ("_objc_retainAutoreleasedReturnValue", .objc, .retainAutoreleasedReturn, false),
            ("_swift_retain", .swift, .retain, false),
            ("_swift_release", .swift, .release, false),
            ("_swift_retain_n", .swift, .retain, true),
            ("_swift_release_n", .swift, .release, true),
            ("_swift_bridgeObjectRetain", .swift, .retain, false),
            ("_swift_unknownObjectRelease", .swift, .release, false),
            ("_swift_nonatomic_release", .swift, .release, false),
        ]
        for (name, family, role, count) in expectations {
            let library = family == .objc ? "/usr/lib/libobjc.A.dylib" : "/usr/lib/swift/libswiftCore.dylib"
            let found = sites(fixture(callTargets: [stubAddress], indirectSymbols: [stub(name, library: library)]))
            guard let identity = found[callerStart] else {
                // Tier 1 is catalog-backed: a name the standard catalog does not declare is
                // not in the set, which is the documented behavior.
                XCTAssertNil(CallSignatureCatalog.standard.signature(for: String(name.dropFirst())), name)
                continue
            }
            XCTAssertEqual(identity.family, family, name)
            XCTAssertEqual(identity.role, role, name)
            XCTAssertEqual(identity.isCountVariant, count, name)
            XCTAssertEqual(identity.importSymbol, String(name.dropFirst()), name)
        }
        // The two roots every Objective-C program uses must be in the catalog-backed set.
        XCTAssertNotNil(ARCCalleeCatalog.entries["objc_retain"])
        XCTAssertNotNil(ARCCalleeCatalog.entries["objc_release"])
    }

    // Q6: library check on the full install name, nil accepted.
    func testLibraryNameRuleFollowsRuling() {
        func classified(_ name: String, library: String?) -> Bool {
            !sites(fixture(callTargets: [stubAddress],
                           indirectSymbols: [stub(name, library: library)])).isEmpty
        }
        XCTAssertTrue(classified("_objc_release", library: "/usr/lib/libobjc.A.dylib"))
        XCTAssertTrue(classified("_objc_release", library: nil))
        XCTAssertFalse(classified("_objc_release", library: "/usr/lib/libSystem.B.dylib"))
        XCTAssertFalse(classified("_objc_release", library: "dynamic lookup"))
        XCTAssertFalse(classified("_objc_release", library: "main executable"))
        XCTAssertFalse(classified("_objc_release", library: "/usr/lib/swift/libswiftCore.dylib"))
        if ARCCalleeCatalog.entries["swift_release"] != nil {
            XCTAssertTrue(classified("_swift_release", library: "/usr/lib/swift/libswiftCore.dylib"))
            XCTAssertTrue(classified("_swift_release", library: nil))
            XCTAssertFalse(classified("_swift_release", library: "/usr/lib/libobjc.A.dylib"))
            XCTAssertFalse(classified("_swift_release", library: "/usr/lib/libSystem.B.dylib"))
        }
        XCTAssertTrue(ARCCalleeCatalog.libraryMatches(nil, family: .objc))
        XCTAssertTrue(ARCCalleeCatalog.libraryMatches("libobjc.A.dylib", family: .objc))
        XCTAssertFalse(ARCCalleeCatalog.libraryMatches("libobjcfake_not/libSystem.dylib", family: .objc))
    }

    func testCallToUnknownAddressIsNotClassified() {
        let value = fixture(callTargets: [0x9999], indirectSymbols: [stub()])
        XCTAssertTrue(sites(value).isEmpty)
    }
}
