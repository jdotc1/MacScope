import Foundation
import XCTest
@testable import MacScope

final class C2TailAdmissionRouteTests: XCTestCase {
    private func row(_ address: UInt64, _ bytes: String, _ mnemonic: String,
                     _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: bytes, mnemonic: mnemonic,
                       operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func offMode(_ body: () -> Void) {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) { body() }
        }
    }

    private func declaredTailSnapshot(
        rows: [InstructionRow], start: UInt64 = 0x1000, end: UInt64? = nil,
        target: UInt64 = 0x2000, sourceName: String = "_declared_source",
        targetName: String = "_declared_callee", callerType: String? = "void",
        calleeType: String? = "void", extras: [FunctionSummary] = [],
        indirectSymbols: [IndirectSymbolSummary] = [], includeCallee: Bool = true
    ) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.functions = [FunctionSummary(id: UUID(), name: sourceName, startAddress: start,
            endAddress: end ?? (rows.last!.address + 4), confidence: 1)]
        if includeCallee {
            analysis.functions.append(FunctionSummary(id: UUID(), name: targetName,
                startAddress: target, endAddress: target + 4, confidence: 1))
        }
        analysis.functions += extras
        analysis.instructions = rows
        analysis.indirectSymbols = indirectSymbols
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "fixture",
            path: "/fixture/declared-tail", kind: "executable", architecture: "arm64", slot: .primary),
            analysis: analysis)
        if let callerType {
            snapshot.addressOverrides[.primary(start)] = AddressOverride(
                signature: .init(returnType: callerType))
        }
        if let calleeType, includeCallee {
            snapshot.addressOverrides[.primary(target)] = AddressOverride(
                signature: .init(returnType: calleeType))
        }
        return snapshot
    }

    private func stub(_ name: String? = "_free", address: UInt64 = 0x2100,
                      section: String = "__TEXT,__stubs", kind: String = MachOIndirectSymbolKind.symbolStub.rawValue,
                      local: Bool = false, absolute: Bool = false, size: UInt32 = 12) -> IndirectSymbolSummary {
        IndirectSymbolSummary(id: UUID(), kind: kind, sourceSection: section,
            address: address, entrySize: size, tableIndex: 0, rawSymbolIndex: 0,
            symbolIndex: 0, symbolName: name, libraryOrdinal: nil, libraryName: nil,
            isLocal: local, isAbsolute: absolute)
    }

    private func input(_ snapshot: WorkspaceSnapshot) -> PseudocodeRenderInput {
        snapshot.pseudocodeRenderInput(selectedAddress: 0x1000, in: .primary)
    }

    private func build(_ input: PseudocodeRenderInput) -> MacIRFunction {
        PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides,
            authoredCallSignaturesByTarget: input.authoredCallSignaturesByTarget,
            knownTailCallTargets: input.knownTailCallTargets, instructions: input.instructions)
    }

    private typealias Site = C2DataflowCensus.TailAdmissionSite

    private func sites(_ snapshot: WorkspaceSnapshot, returnContractEnabled: Bool = false,
                       map: [UInt64: String]? = nil,
                       authored: ((String) -> String?)? = nil,
                       catalog: ((String) -> String?)? = nil) -> [Site] {
        let handoff = input(snapshot)
        let function = build(handoff)
        let starts = Set((snapshot.analysis(in: .primary)?.functions ?? []).map(\.startAddress))
        return C2DataflowCensus.tailAdmissionSites(function: function,
            knownTailCallTargets: map ?? handoff.knownTailCallTargets, functionStarts: starts,
            authoredReturnType: authored ?? { handoff.authoredCallSignaturesByTarget[$0]?.returnType },
            catalogReturnType: catalog ?? { CallSignatureCatalog.standard.signature(for: $0)?.returnType },
            returnContractEnabled: returnContractEnabled)
    }

    private func entry(_ type: String? = nil) -> WorkspaceSnapshot {
        declaredTailSnapshot(rows: [row(0x1000, "00 04 00 14", "b", "0x2000")], calleeType: type)
    }

    private func imported(_ name: String = "_free") -> WorkspaceSnapshot {
        declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
            indirectSymbols: [stub(name)], includeCallee: false)
    }

    private func assertSummary(_ object: [String: Any], counts: [String: Int], functions: [String: Int],
                               targets: [String: Int], total: Int, newly: Int,
                               on: Bool = false, ssa: Bool = true, cite: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(Set(object.keys), Set(["schemaVersion", "returnContractEnabled", "ssaEnabled", "classified",
            "sites", "functions", "targets", "sitesTotal", "newlyAdmittedByItem795Sites", "basis"]), cite, file: file, line: line)
        XCTAssertEqual(object["schemaVersion"] as? Int, 1, cite, file: file, line: line)
        XCTAssertEqual(object["returnContractEnabled"] as? Bool, on, cite, file: file, line: line)
        XCTAssertEqual(object["classified"] as? Bool, !on, cite, file: file, line: line)
        XCTAssertEqual(object["ssaEnabled"] as? Bool, ssa, cite, file: file, line: line)
        XCTAssertEqual(object["sites"] as? [String: Int], counts, cite, file: file, line: line)
        XCTAssertEqual(object["functions"] as? [String: Int], functions, cite, file: file, line: line)
        XCTAssertEqual(object["targets"] as? [String: Int], targets, cite, file: file, line: line)
        XCTAssertEqual(object["sitesTotal"] as? Int, total, cite, file: file, line: line)
        XCTAssertEqual(object["newlyAdmittedByItem795Sites"] as? Int, newly, cite, file: file, line: line)
        XCTAssertEqual(object["basis"] as? String, "realized call-phase tail effects in the built function; functions and targets are distinct counts per route; declaredVoidEntry is the pre-795 route, narrowed at P by unique-name and non-stub guards, so it is not a before/after delta by itself", cite, file: file, line: line)
        XCTAssertTrue(JSONSerialization.isValidJSONObject(object), cite, file: file, line: line)
    }

    func testA1UndeclaredEntry() {
        offMode {
            XCTAssertEqual(sites(entry()), [Site(address: 0x1000, target: 0x2000, route: .undeclaredEntry)],
                "AnalysisModels+WorkspaceSnapshot.swift:2047-2048 admits undeclared entries")
        }
    }

    func testA2DeclaredVoidEntry() {
        offMode {
            XCTAssertEqual(sites(entry("void")), [Site(address: 0x1000, target: 0x2000, route: .declaredVoidEntry)],
                "AnalysisModels+WorkspaceSnapshot.swift:2047-2048 preserves the declared-void route")
        }
    }

    func testA3CatalogVoidStub() {
        offMode {
            XCTAssertEqual(sites(imported()), [Site(address: 0x1000, target: 0x2100, route: .importStubCatalogVoid)],
                "AnalysisModels+WorkspaceSnapshot.swift:2087,2095; CallSignatureCatalog.swift:186 (_free is void)")
        }
    }

    func testA4CatalogAbsentStub() {
        offMode {
            XCTAssertEqual(sites(imported("_mscope_uncatalogued_stub")),
                [Site(address: 0x1000, target: 0x2100, route: .importStubCatalogAbsent)],
                "AnalysisModels+WorkspaceSnapshot.swift:2095 admits catalog-absent stubs")
        }
    }

    func testA5NonemptyMapWithoutTailSite() {
        offMode {
            let snapshot = declaredTailSnapshot(rows: [row(0x1000, "c0 03 5f d6", "ret", "")])
            XCTAssertEqual(input(snapshot).knownTailCallTargets, [0x2000: "_declared_callee"],
                "AnalysisModels+WorkspaceSnapshot.swift:2057 is an image-wide map, not realized sites")
            let realized = sites(snapshot)
            XCTAssertEqual(realized, [], "MacIRBuilder+TailCalls.swift:526; a ret row has no call-phase tail effect")
            var tally = C2DataflowCensus.TailAdmissionTally()
            tally.add(functionStart: 0x1000, sites: realized)
            let zero = ["declaredVoidEntry": 0, "undeclaredEntry": 0, "importStubCatalogVoid": 0,
                        "importStubCatalogAbsent": 0, "unclassified": 0]
            assertSummary(tally.summaryObject(returnContractEnabled: false, ssaEnabled: true),
                counts: zero, functions: zero, targets: zero, total: 0, newly: 0,
                cite: "AnalysisModels+WorkspaceSnapshot.swift:2057; empty realized sites add nothing")
        }
    }

    func testA6ReturnContractOnIsUnclassified() {
        offMode {
            let realized = sites(entry(), returnContractEnabled: true)
            XCTAssertEqual(realized, [Site(address: 0x1000, target: 0x2000, route: .unclassified)],
                "AnalysisModels+WorkspaceSnapshot.swift:1994 has no off-mode route axis")
            var tally = C2DataflowCensus.TailAdmissionTally()
            tally.add(functionStart: 0x1000, sites: realized)
            let counts = ["declaredVoidEntry": 0, "undeclaredEntry": 0, "importStubCatalogVoid": 0,
                          "importStubCatalogAbsent": 0, "unclassified": 1]
            assertSummary(tally.summaryObject(returnContractEnabled: true, ssaEnabled: true),
                counts: counts, functions: counts, targets: counts, total: 1, newly: 0, on: true,
                cite: "AnalysisModels+WorkspaceSnapshot.swift:1994; on-mode must not classify")
        }
    }

    func testA7MissingAndMismatchedMapDoNotDropSites() {
        offMode {
            let expected = [Site(address: 0x1000, target: 0x2000, route: .unclassified)]
            XCTAssertEqual(sites(entry(), map: [:]), expected,
                "MacIRBuilder+TailCalls.swift:560-562 binds the effect target to the admitted map")
            XCTAssertEqual(sites(entry(), map: [0x2000: "_different"]), expected,
                "MacIRBuilder+TailCalls.swift:562; mismatched name is unclassified, not dropped")
        }
    }

    func testA8FourRouteTally() {
        offMode {
            var tally = C2DataflowCensus.TailAdmissionTally()
            tally.add(functionStart: 0x1000, sites: sites(entry()))
            tally.add(functionStart: 0x1100, sites: sites(entry("void")))
            tally.add(functionStart: 0x1200, sites: sites(imported()))
            tally.add(functionStart: 0x1300, sites: sites(imported("_mscope_uncatalogued_stub")))
            let counts = ["declaredVoidEntry": 1, "undeclaredEntry": 1, "importStubCatalogVoid": 1,
                          "importStubCatalogAbsent": 1, "unclassified": 0]
            assertSummary(tally.summaryObject(returnContractEnabled: false, ssaEnabled: true),
                counts: counts, functions: counts, targets: counts, total: 4, newly: 3,
                cite: "AnalysisModels+WorkspaceSnapshot.swift:2047,2087,2095; four disjoint route buckets")
        }
    }

    func testA9DistinctFunctionsAndTargets() {
        offMode {
            let realized = sites(entry())
            var tally = C2DataflowCensus.TailAdmissionTally()
            tally.add(functionStart: 0x1000, sites: realized)
            tally.add(functionStart: 0x1100, sites: realized)
            let counts = ["declaredVoidEntry": 0, "undeclaredEntry": 2, "importStubCatalogVoid": 0,
                          "importStubCatalogAbsent": 0, "unclassified": 0]
            let targets = ["declaredVoidEntry": 0, "undeclaredEntry": 1, "importStubCatalogVoid": 0,
                           "importStubCatalogAbsent": 0, "unclassified": 0]
            assertSummary(tally.summaryObject(returnContractEnabled: false, ssaEnabled: true),
                counts: counts, functions: counts, targets: targets, total: 2, newly: 2,
                cite: "AnalysisModels+WorkspaceSnapshot.swift:2057; shared map targets are distinct, sites are occurrences")
            tally.add(functionStart: 0x1100, sites: realized)
            let three = ["declaredVoidEntry": 0, "undeclaredEntry": 3, "importStubCatalogVoid": 0,
                         "importStubCatalogAbsent": 0, "unclassified": 0]
            assertSummary(tally.summaryObject(returnContractEnabled: false, ssaEnabled: true),
                counts: three, functions: counts, targets: targets, total: 3, newly: 3,
                cite: "AnalysisModels+WorkspaceSnapshot.swift:2057; repeated function sites do not duplicate function identity")
        }
    }

    func testA10EmptyTallyHasAllFifteenZeros() {
        let tally = C2DataflowCensus.TailAdmissionTally()
        let zero = ["declaredVoidEntry": 0, "undeclaredEntry": 0, "importStubCatalogVoid": 0,
                    "importStubCatalogAbsent": 0, "unclassified": 0]
        assertSummary(tally.summaryObject(returnContractEnabled: true, ssaEnabled: false),
            counts: zero, functions: zero, targets: zero, total: 0, newly: 0, on: true, ssa: false,
            cite: "AnalysisModels+WorkspaceSnapshot.swift:1994,2020; DecompilerC2DataflowCensusTests.swift:2727-2728,2936; mode truthfulness")
    }

    func testUnexpectedReturnTypesAreUnclassified() {
        offMode {
            XCTAssertEqual(sites(entry(), authored: { _ in "int" }),
                [Site(address: 0x1000, target: 0x2000, route: .unclassified)],
                "AnalysisModels+WorkspaceSnapshot.swift:2047; unexpected authored return type is a drift alarm")
            XCTAssertEqual(sites(imported(), catalog: { _ in "int" }),
                [Site(address: 0x1000, target: 0x2100, route: .unclassified)],
                "AnalysisModels+WorkspaceSnapshot.swift:2095; unexpected catalog return type is a drift alarm")
        }
    }
}
