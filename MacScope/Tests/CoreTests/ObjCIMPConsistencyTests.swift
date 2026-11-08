import Foundation
import XCTest
@testable import MacScope

final class ObjCIMPConsistencyTests: XCTestCase {
    private func method(_ selector: String, _ imp: UInt64?, classMethod: Bool = false) -> ObjCMethod {
        ObjCMethod(selector: selector, typeEncoding: nil, isClassMethod: classMethod, implementation: imp)
    }

    private func cls(_ name: String, instance: [ObjCMethod] = [], classMethods: [ObjCMethod] = []) -> ObjCClass {
        ObjCClass(name: name, superclassName: nil, adoptedProtocols: [], classMethods: classMethods,
                  instanceMethods: instance, ivars: [], properties: [])
    }

    private func category(_ name: String, owner: String, instance: [ObjCMethod] = [],
                          classMethods: [ObjCMethod] = []) -> ObjCCategory {
        ObjCCategory(name: name, className: owner, classMethods: classMethods,
                     instanceMethods: instance, adoptedProtocols: [], properties: [])
    }

    private func function(_ start: UInt64, _ end: UInt64, _ name: String) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func section(_ name: String, size: UInt64) -> SectionSummary {
        SectionSummary(id: UUID(), name: name, address: 0x5000, size: size,
                       fileOffset: 0, isExecutable: false, isZeroFill: false,
                       fileSize: size, coffCoordinate: nil)
    }

    func testEveryMethodEntryHasItsOwnRowAndIndependentSharingFlag() throws {
        let functions = [
            function(0x1000, 0x1010, "sub_A"),
            function(0x2000, 0x2004, "ClassPlus"),
            function(0x4000, 0x4010, "Cat")
        ]
        let classes = [cls("Owner", instance: [
            method("first", 0x1000), method("inside", 0x1004), method("outside", 0x3000),
            method("alias", 0x1000), method("missing", nil), method("zero", 0)
        ], classMethods: [method("build", 0x2000, classMethod: true)])]
        let categories = [category("Extra", owner: "Owner", instance: [method("extend", 0x4000)])]
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: functions, classes: classes, categories: categories,
            sections: [section("__DATA_CONST,__objc_classlist", size: 8),
                       section("__DATA_CONST,__objc_catlist", size: 8)])
        XCTAssertEqual(report.rows.count, 6)
        XCTAssertEqual(report.rows.map(\.method), [
            "-[Owner first]", "-[Owner inside]", "-[Owner outside]", "-[Owner alias]",
            "+[Owner build]", "-[Owner(Extra) extend]"
        ])
        XCTAssertEqual(report.rows.map(\.sharedBy), [2, 1, 1, 2, 1, 1])
        XCTAssertNil(report.rows[0].mismatch)
        XCTAssertEqual(report.rows[0].containingFunction?.start, 0x1000)
        XCTAssertEqual(report.rows[0].containingFunction?.end, 0x1010)
        XCTAssertEqual(report.rows[0].containingFunction?.name, "sub_A")
        XCTAssertEqual(report.rows[1].mismatch, .insideFunction(offset: 4))
        XCTAssertEqual(report.rows[1].containingFunction?.name, "sub_A")
        XCTAssertEqual(report.rows[2].mismatch, .notInAnyFunction)
        XCTAssertNil(report.rows[2].containingFunction)
        XCTAssertNil(report.rows[3].mismatch)
        XCTAssertNil(report.rows[4].mismatch)
        XCTAssertNil(report.rows[5].mismatch)
        XCTAssertEqual(report.containers.map(\.declaredEntries), [1, 1])
        XCTAssertEqual(report.containers.map(\.parsedContainers), [1, 1])
        XCTAssertTrue(report.containers.allSatisfy { $0.issues.isEmpty })
        XCTAssertEqual(report.invalidFunctionExtents, 0)
        XCTAssertEqual(functions.map(\.name), ["sub_A", "ClassPlus", "Cat"])
        XCTAssertEqual(classes[0].instanceMethods.count, 6)
    }

    func testSharedInsideIMPRemainsAMismatchOnBothRows() {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [function(0x1000, 0x1010, "container")],
            classes: [cls("Owner", instance: [method("same", 0x1004), method("same", 0x1004)])],
            categories: [], sections: [])
        XCTAssertEqual(report.rows.count, 2)
        XCTAssertEqual(report.rows.map(\.sharedBy), [2, 2])
        XCTAssertTrue(report.rows.allSatisfy { $0.mismatch == .insideFunction(offset: 4) })
        XCTAssertEqual(report.rows.map(\.method), ["-[Owner same]", "-[Owner same]"])
    }

    func testExactStartWinsOverAnOverlappingEarlierContainer() {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [function(0x1000, 0x3000, "wide"), function(0x2000, 0x2100, "exact")],
            classes: [cls("Owner", instance: [method("entry", 0x2000), method("overlap", 0x2004)])],
            categories: [], sections: [])
        XCTAssertNil(report.rows[0].mismatch)
        XCTAssertEqual(report.rows[0].containingFunction?.name, "exact")
        XCTAssertEqual(report.rows[1].containingFunction?.name, "wide")
        XCTAssertEqual(report.rows[1].mismatch, .insideFunction(offset: 0x1004))
    }

    func testNestedIntervalsAndUnsortedFunctionsDoNotHideAContainer() {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [function(0x2000, 0x2010, "short"), function(0x1000, 0x4000, "wide"),
                        function(0x5000, 0x5010, "later")],
            classes: [cls("Owner", instance: [method("middle", 0x3000), method("end", 0x4000)])],
            categories: [], sections: [])
        XCTAssertEqual(report.rows[0].containingFunction?.name, "wide")
        XCTAssertEqual(report.rows[0].mismatch, .insideFunction(offset: 0x2000))
        XCTAssertEqual(report.rows[1].mismatch, .notInAnyFunction)
        XCTAssertNil(report.rows[1].containingFunction)
    }

    func testZeroWidthMaximumAddressAndInvalidExtentAreSafe() {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [function(UInt64.max, UInt64.max, "point"), function(0x3000, 0x2000, "invalid")],
            classes: [cls("Owner", instance: [method("point", UInt64.max), method("invalid", 0x3000)])],
            categories: [], sections: [])
        XCTAssertNil(report.rows[0].mismatch)
        XCTAssertEqual(report.rows[0].containingFunction?.name, "point")
        XCTAssertEqual(report.rows[1].mismatch, .notInAnyFunction)
        XCTAssertEqual(report.invalidFunctionExtents, 1)
    }

    func testUnalignedIMPIsReportedRatherThanSilentlyDiscarded() {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [function(0x1000, 0x1010, "body")],
            classes: [cls("Owner", instance: [method("unaligned", 0x1001)])],
            categories: [], sections: [])
        XCTAssertEqual(report.rows.count, 1)
        XCTAssertEqual(report.rows[0].mismatch, .insideFunction(offset: 1))
    }

    func testDroppedContainersAreVisibleWithoutInventingMethodRows() throws {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [], classes: [cls("A")], categories: [],
            sections: [section("__objc_classlist", size: 3 * 8),
                       section("__DATA_CONST,__objc_catlist", size: 21 * 8)])
        XCTAssertTrue(report.rows.isEmpty)
        let classes = try XCTUnwrap(report.containers.first { $0.section == "__objc_classlist" })
        XCTAssertEqual(classes.declaredEntries, 3)
        XCTAssertEqual(classes.parsedContainers, 1)
        XCTAssertEqual(classes.issues, [.parsedCountShortfall])
        let categories = try XCTUnwrap(report.containers.first { $0.section == "__objc_catlist" })
        XCTAssertEqual(categories.declaredEntries, 21)
        XCTAssertEqual(categories.parsedContainers, 0)
        XCTAssertEqual(categories.issues, [.parsedCountShortfall])
    }

    func testCoverageCombinesSectionsAndDisclosesPartialSlotsAndMissingMetadata() throws {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [], classes: [cls("A"), cls("B")], categories: [],
            sections: [section("__DATA,__objc_classlist", size: 8),
                       section("__DATA_CONST,__objc_classlist", size: 9)])
        let classes = try XCTUnwrap(report.containers.first)
        XCTAssertEqual(classes.sectionCount, 2)
        XCTAssertEqual(classes.declaredEntries, 2)
        XCTAssertEqual(classes.parsedContainers, 2)
        XCTAssertEqual(classes.issues, [.partialPointerSlot])
        let categories = try XCTUnwrap(report.containers.last)
        XCTAssertEqual(categories.sectionCount, 0)
        XCTAssertNil(categories.declaredEntries)
        XCTAssertEqual(categories.issues, [.sectionMetadataMissing])
    }

    func testCoverageOverflowDoesNotWrapOrClaimAShortfall() throws {
        let sections = (0..<9).map { _ in section("__objc_catlist", size: UInt64.max) }
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [], classes: [], categories: [], sections: sections)
        let coverage = try XCTUnwrap(report.containers.last)
        XCTAssertNil(coverage.declaredEntries)
        XCTAssertEqual(coverage.issues, [.partialPointerSlot, .entryCountOverflow])
    }

    func testParsedCountAboveSlotsIsDisclosedAndCategoryTextIsNotJudgedSemantically() throws {
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: [function(0x1000, 0x1010, "sub_body")], classes: [],
            categories: [category("ShellExecution", owner: "NSString",
                                  classMethods: [method("mco_object", 0x1000, classMethod: true)])],
            sections: [section("__objc_classlist", size: 0), section("__objc_catlist", size: 0)])
        XCTAssertEqual(report.rows[0].method, "+[NSString(ShellExecution) mco_object]")
        XCTAssertNil(report.rows[0].mismatch)
        XCTAssertEqual(report.rows[0].containingFunction?.name, "sub_body")
        XCTAssertEqual(report.containers.last?.issues, [.parsedCountExceedsSlots])
    }

    func testCategoryFixtureAnalysisReportsBothIMPsAsExactStarts() throws {
        let fixture = MachOFixture.makeExecutableWithCategoryOnlyRelativeIMPs()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("objc-w2-\(UUID().uuidString)")
        try fixture.bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let snapshot = try AnalysisEngine().analyze(url: url)
        let report = AnalysisEngine.auditObjCMethodImplementations(
            functions: snapshot.functions, classes: snapshot.objcClasses,
            categories: snapshot.objcCategories, sections: snapshot.sections)
        XCTAssertEqual(report.rows.count, 2)
        XCTAssertEqual(Set(report.rows.map(\.implementation)),
                       [fixture.baseAddress + 0x20, fixture.baseAddress + 0x30])
        XCTAssertEqual(report.rows.map(\.method), ["-[Owner(Extra) first]", "+[Owner(Extra) second]"])
        XCTAssertTrue(report.rows.allSatisfy { $0.mismatch == nil && $0.sharedBy == 1 })
        XCTAssertTrue(report.rows.allSatisfy { $0.containingFunction?.start == $0.implementation })
        XCTAssertEqual(report.containers.map(\.declaredEntries), [1, 1])
        XCTAssertEqual(report.containers.map(\.parsedContainers), [1, 1])
        XCTAssertTrue(report.containers.allSatisfy { $0.issues.isEmpty })
    }
}
