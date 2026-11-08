import XCTest
@testable import MacScope

final class ObjectiveCProtocolRendererTests: XCTestCase {
    private func record(_ name: String = "Printable", _ address: UInt64 = 0x1000,
                        inherited: [String] = [], required: [ObjCMethod] = [],
                        optional: [ObjCMethod] = [], properties: [ObjCProperty] = []) -> ObjCProtocol {
        ObjCProtocol(name: name, address: address, adoptedProtocols: inherited,
                     requiredMethods: required, optionalMethods: optional, properties: properties)
    }
    private func render(_ records: [ObjCProtocol]) -> String {
        ObjectiveCProtocolRenderer.render(protocols: records)
    }
    func testProtocolOnlyAndInheritedOrder() {
        let text = render([record(inherited: ["First", "External", "First"])])
        XCTAssertTrue(text.contains("@protocol Printable <First, External, First>\n@end"))
        XCTAssertTrue(text.contains("completeness unknown"))
        XCTAssertTrue(text.contains("unresolved references"))
    }
    func testRequiredOptionalAndClassInstanceFlagsKeepOrder() {
        let text = render([record(required: [
            ObjCMethod(selector: "build", typeEncoding: "@16@0:8", isClassMethod: true),
            ObjCMethod(selector: "write:", typeEncoding: nil, isClassMethod: false)], optional: [
            ObjCMethod(selector: "cleanup", typeEncoding: "v16@0:8", isClassMethod: false)])])
        XCTAssertTrue(text.contains("@required\n+ (id)build;\n- (id)write:(id)arg0;\n@optional\n- (void)cleanup;"))
    }
    func testImplementationDoesNotBecomeBodyOrAddressEvidence() {
        let text = render([record(required: [ObjCMethod(selector: "run", typeEncoding: nil,
                                                       isClassMethod: false, implementation: 0xdeadbeef)])])
        XCTAssertTrue(text.contains("- (id)run;"))
        XCTAssertFalse(text.contains("deadbeef"))
        XCTAssertFalse(text.contains("{"))
    }
    func testPropertiesAreUnclassifiedCommentsBeforeDeclaration() {
        let text = render([record(properties: [ObjCProperty(name: "title", attributes: "T@,R")])])
        XCTAssertTrue(text.contains("requirement UNKNOWN; class/instance UNKNOWN"))
        XCTAssertTrue(text.contains("name=title; attributes=T@,R\n@protocol Printable"))
        XCTAssertFalse(text.contains("@property"))
        XCTAssertFalse(text.contains("@required"))
    }
    func testIdenticalDuplicateDeduplicatesOnlyExactRecord() {
        let value = record()
        XCTAssertEqual(render([value, value]), render([value]))
        // Canonically equivalent Swift strings are distinct retained spellings.
        let composed = record("\u{e9}")
        let decomposed = record("e\u{301}")
        let distinct = render([composed, decomposed])
        XCTAssertTrue(distinct.contains("Ambiguous"))
        XCTAssertTrue(distinct.contains("\\u{e9}"))
        XCTAssertTrue(distinct.contains("e\\u{301}"))
    }
    func testConflictingSameAddressDoesNotChooseName() {
        let text = render([record("First"), record("Second")])
        XCTAssertFalse(text.contains("@protocol"))
        XCTAssertTrue(text.contains("0x1000: First"))
        XCTAssertTrue(text.contains("0x1000: Second"))
    }
    func testConflictingNameDifferentAddressesDoesNotChooseDescriptor() {
        for records in [[record("Same", 1), record("Same", 2)], [record("Same", 2), record("Same", 1)]] {
            let text = render(records)
            XCTAssertFalse(text.contains("@protocol"))
            XCTAssertTrue(text.contains("0x1: Same"))
            XCTAssertTrue(text.contains("0x2: Same"))
        }
    }
    func testSameAddressDifferentRequirementsAreAmbiguous() {
        let text = render([record(), record(required: [ObjCMethod(selector: "x", typeEncoding: nil, isClassMethod: false)])])
        XCTAssertFalse(text.contains("@protocol"))
        XCTAssertTrue(text.contains("Ambiguous"))
        let method = ObjCMethod(selector: "x", typeEncoding: nil, isClassMethod: false)
        let withIMP = ObjCMethod(selector: "x", typeEncoding: nil, isClassMethod: false, implementation: 1)
        for records in [
            [record(required: [method]), record(optional: [method])],
            [record(required: [method]), record(required: [withIMP])],
            [record(inherited: ["A", "B"]), record(inherited: ["B", "A"])],
            [record(properties: [ObjCProperty(name: "\u{e9}", attributes: "T@")]),
             record(properties: [ObjCProperty(name: "e\u{301}", attributes: "T@")])]
        ] {
            XCTAssertFalse(render(records).contains("@protocol"))
            XCTAssertTrue(render(records).contains("Ambiguous"))
        }
    }
    func testMalformedNamesAndSelectorsStayComments() {
        let text = render([record("Bad\n@end"), record("Good", 2, inherited: ["X\n@end"], required: [
            ObjCMethod(selector: "x:broken", typeEncoding: nil, isClassMethod: false),
            ObjCMethod(selector: "x::", typeEncoding: nil, isClassMethod: true)])])
        XCTAssertFalse(text.contains("\n@end\n@end"))
        XCTAssertTrue(text.contains("Bad\\u{a}@end"))
        XCTAssertTrue(text.contains("Unsupported inherited reference"))
        XCTAssertTrue(text.contains("Unsupported recovered method"))
        XCTAssertFalse(text.contains("- (id)x"))
    }
    func testPropertyControlsAndCommentTerminatorsCannotEscape() {
        let text = render([record(properties: [ObjCProperty(name: "*/\n@evil", attributes: "\\\u{2028}\r")])])
        XCTAssertTrue(text.contains("*\\u{2f}\\u{a}@evil"))
        XCTAssertTrue(text.contains("\\u{5c}\\u{2028}\\u{d}"))
        XCTAssertFalse(text.contains("\u{2028}"))
        XCTAssertFalse(text.contains("\n@evil"))
    }
    func testEncodingCannotInjectDeclaration() {
        let text = render([record(required: [ObjCMethod(selector: "value", typeEncoding: "@\"X);evil();\"", isClassMethod: false)])])
        XCTAssertTrue(text.contains("type/selector display refused"))
        XCTAssertFalse(text.contains("evil()"))
    }
    func testExistingSupportedTypeFormatterStillUsed() {
        let method = ObjCMethod(selector: "setPoint:", typeEncoding: "v24@0:8{Point=ii}16", isClassMethod: false)
        XCTAssertTrue(render([record(required: [method])]).contains(ObjCTypeEncoding.methodSignature(method)))
    }
    func testStableObservedOrderAndEmptyWording() {
        let records = [record("Second", 2), record("First", 1)]
        XCTAssertEqual(render(records), render(records))
        XCTAssertTrue(render(records).contains("@end\n// Recovered descriptor 0x1"))
        XCTAssertTrue(render([]).contains("absence is not completeness"))
        XCTAssertFalse(render([]).contains("@protocol"))
        XCTAssertTrue(render([record()]).contains("No members were recovered for this descriptor; completeness unknown"))
    }
    func testInputLimitRefusesAtomically() {
        XCTAssertTrue(render(Array(repeating: record(), count: 1_025)).contains("input exceeds bounded limits"))
        XCTAssertTrue(render([record(String(repeating: "x", count: 4_097))]).contains("input exceeds bounded limits"))
        XCTAssertTrue(render([record(inherited: Array(repeating: "A", count: 4_097))]).contains("input exceeds bounded limits"))
        let largeProperty = ObjCProperty(name: String(repeating: "x", count: 4_096), attributes: "T@")
        XCTAssertTrue(render([record(properties: Array(repeating: largeProperty, count: 257))]).contains("input exceeds bounded limits"))
        // Each escaped name remains below per-string/aggregate input limits but expands output.
        let expanding = ObjCProperty(name: String(repeating: "\u{7f}", count: 160), attributes: "")
        let refused = render([record(properties: Array(repeating: expanding, count: 4_096))])
        XCTAssertTrue(refused.contains("output exceeds bounded limits"))
        XCTAssertFalse(refused.contains("@protocol"))
    }
    func testDiagnosticLengthIsBoundedAndExplicit() {
        let text = render([record(properties: [ObjCProperty(name: String(repeating: "x", count: 200), attributes: "T@")])])
        XCTAssertTrue(text.contains("...[truncated]"))
    }
    func testRequestedImageIsolationAndDefaultUnchanged() {
        let other = ImageSlot(rawValue: 1)
        var primary = ImageAnalysis()
        primary.objcProtocols = [record(required: [ObjCMethod(selector: "primary", typeEncoding: nil, isClassMethod: false)])]
        var sibling = ImageAnalysis()
        sibling.objcProtocols = [record(required: [ObjCMethod(selector: "secondary", typeEncoding: nil, isClassMethod: true)])]
        let snapshot = WorkspaceSnapshot(binaries: [
            BinaryImage(id: UUID(), name: "Primary", path: "/fixtures/primary", kind: "Mach-O", architecture: "arm64", slot: .primary),
            BinaryImage(id: UUID(), name: "Other", path: "/fixtures/other", kind: "Mach-O", architecture: "arm64", slot: other)
        ], analysisBySlot: [.primary: primary, other: sibling])
        let service = DocumentExportService()
        let text = service.renderObjectiveCProtocols(snapshot: snapshot, in: other)
        XCTAssertTrue(text.contains("+ (id)secondary;"))
        XCTAssertFalse(text.contains("- (id)primary;"))
        XCTAssertEqual(service.renderObjectiveCHeader(snapshot: snapshot), "// No Objective-C classes were recovered from this binary.\n")
        XCTAssertEqual(service.renderObjectiveCHeader(snapshot: snapshot, in: other), service.renderObjectiveCHeader(snapshot: snapshot))
        XCTAssertTrue(service.renderObjectiveCProtocols(snapshot: snapshot, in: ImageSlot(rawValue: 99)).contains("requested image slot is absent"))
    }
    func testLegacyClassAndCategoryOutputRemainsExact() {
        let cls = ObjCClass(name: "Plain", superclassName: nil, adoptedProtocols: [], classMethods: [], instanceMethods: [], ivars: [], properties: [])
        let category = ObjCCategory(name: "Extras", className: "Plain", classMethods: [], instanceMethods: [], adoptedProtocols: [], properties: [])
        XCTAssertEqual(ObjectiveCHeaderRenderer.render(classes: [cls], categories: [category]), "@interface Plain\n@end\n\n@interface Plain (Extras)\n@end")
    }
}
