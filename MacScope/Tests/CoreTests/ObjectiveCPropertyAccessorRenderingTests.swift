import XCTest
@testable import MacScope

final class ObjectiveCPropertyAccessorRenderingTests: XCTestCase {
    private func header(_ attributes: String, name: String = "value", category: Bool = false) -> String {
        let property = ObjCProperty(name: name, attributes: attributes)
        if category {
            let category = ObjCCategory(name: "Extras", className: "Sample", classMethods: [],
                                        instanceMethods: [], adoptedProtocols: [], properties: [property])
            return ObjectiveCHeaderRenderer.render(classes: [], categories: [category])
        }
        let cls = ObjCClass(name: "Sample", superclassName: nil, adoptedProtocols: [],
                            classMethods: [], instanceMethods: [], ivars: [], properties: [property])
        return ObjectiveCHeaderRenderer.render(classes: [cls])
    }

    private func propertyLine(_ attributes: String, category: Bool = false) -> String {
        String(header(attributes, category: category).split(separator: "\n")[1])
    }

    private func assertRefused(_ attributes: String, file: StaticString = #filePath, line: UInt = #line) {
        let output = header(attributes)
        XCTAssertFalse(output.contains("@property"), output, file: file, line: line)
        XCTAssertTrue(output.contains("/* Property accessor metadata refused ("), output, file: file, line: line)
        XCTAssertEqual(output.split(separator: "\n", omittingEmptySubsequences: false).count, 3, file: file, line: line)
        XCTAssertLessThan(output.utf8.count, 700, file: file, line: line)
    }

    func testExactGetterCase() {
        XCTAssertEqual(propertyLine("Ti,GreadVALUE"), "@property (getter=readVALUE) int value;")
    }

    func testExactSetterColon() {
        XCTAssertEqual(propertyLine("Ti,SwriteVALUE:"), "@property (setter=writeVALUE:) int value;")
    }

    func testBothAccessorsRetainMemoryAtomicityAndTypeFormatting() {
        XCTAssertEqual(propertyLine("T@\"NSString\",C,N,GreadValue,SwriteValue:"),
                       "@property (copy, nonatomic, getter=readValue, setter=writeValue:) NSString *value;")
    }

    func testReadonlyWithGetter() {
        XCTAssertEqual(propertyLine("TB,R,GisReady"), "@property (readonly, getter=isReady) BOOL value;")
    }

    func testNoAccessorLegacyOutputExactlyPreserved() {
        XCTAssertEqual(header("T@\"NSString\",&,N,V_value,D"),
                       "@interface Sample\n@property (strong, nonatomic) NSString *value;\n@end")
        XCTAssertEqual(propertyLine("Ti"), "@property int value;")
        XCTAssertEqual(propertyLine("T@,W,N,R"), "@property (weak, nonatomic, readonly) id value;")
    }

    func testIdenticalDuplicatesCollapseInFixedOrder() {
        XCTAssertEqual(propertyLine("Ti,Swrite:,Gread,Gread,Swrite:"),
                       "@property (getter=read, setter=write:) int value;")
    }

    func testConflictingGetterAndSetterDuplicatesRefuse() {
        assertRefused("Ti,Gfirst,Gsecond")
        assertRefused("Ti,Sfirst:,Ssecond:")
        assertRefused("Ti,Gsecond,Gfirst")
        assertRefused("Ti,Ssecond:,Sfirst:")
    }

    func testCanonicallyEquivalentButByteDifferentDuplicatesRefuse() {
        assertRefused("Ti,Gcaf\u{e9},Gcafe\u{301}")
    }

    func testEmptyGetterAndSetterRefuse() {
        assertRefused("Ti,G")
        assertRefused("Ti,S")
        assertRefused("Ti,S:")
    }

    func testIncorrectArityRefusesWithoutRepair() {
        for accessor in ["Gread:", "Swrite", "Swrite::", "Swrite:other:", "S:write:"] {
            assertRefused("Ti," + accessor)
        }
    }

    func testWhitespaceControlsAndSourceInjectionRefuse() {
        for accessor in ["G read", "Gread ", "Gread\t", "Gread\r\nint injected;",
                         "Gread\0", "Gread\u{7f}", "Gread\u{2028}", "Gread\u{2029}",
                         "Gread\u{200d}", "Gread*/\nint injected;/*", "Swrite;evil:",
                         "Gread-name", "G7read", "Gread\"", "Gread\\",
                         "G\u{301}read", "S\u{301}write:",
                         "G\u{200d}read", "S\u{200d}write:"] {
            assertRefused("Ti," + accessor)
        }
    }

    func testReadonlySetterRefusesRegardlessOfOrder() {
        assertRefused("Ti,R,Swrite:")
        assertRefused("Ti,Swrite:,R")
        assertRefused("Ti,Gread,R,Swrite:")
        assertRefused("Ti,R\u{301},Swrite:")
        assertRefused("Ti,Swrite:,R\u{301}")
    }

    func testUnknownTypeStillUsesExistingIdFallback() {
        XCTAssertEqual(propertyLine("T???,Gread,Swrite:"),
                       "@property (getter=read, setter=write:) id value;")
        XCTAssertEqual(propertyLine("T???,V_value"), "@property id value;")
    }

    func testClassAndCategoryShareValidAndRefusalRendering() {
        for attributes in ["Ti,Gread,Swrite:", "Ti,R,Swrite:", "Ti,Gbad*/\ncode"] {
            XCTAssertEqual(propertyLine(attributes), propertyLine(attributes, category: true))
        }
    }

    func testRefusalEscapesBothContextFieldsAndCommentTerminator() {
        let output = header("Ti,Gbad*/\nint injected;/*", name: "evil*/\n@property int injected;/*")
        let lines = output.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.count, 3)
        let diagnostic = String(lines[1])
        XCTAssertTrue(diagnostic.hasPrefix("/* Property accessor metadata refused ("))
        XCTAssertTrue(diagnostic.hasSuffix(" */"))
        XCTAssertFalse(String(diagnostic.dropFirst(2).dropLast(2)).contains("*/"))
        XCTAssertTrue(diagnostic.contains("\\u{2a}\\u{2f}\\u{a}"))
        XCTAssertFalse(lines.contains { $0.hasPrefix("@property") || $0.hasPrefix("int injected") })
    }

    func testDiagnosticIsDeterministicAndBoundedForLongContexts() {
        let attributes = "Ti,G" + String(repeating: "x", count: 1024)
        let name = String(repeating: "\u{2028}*/", count: 1024)
        let first = header(attributes, name: name)
        XCTAssertEqual(first, header(attributes, name: name))
        XCTAssertLessThan(first.utf8.count, 700)
        XCTAssertTrue(first.contains("..."))
        XCTAssertFalse(first.contains("@property"))
        XCTAssertEqual(first.split(separator: "\n").count, 3)
    }

    func testSelectorByteCeilingIncludesSetterColon() {
        let getter = String(repeating: "g", count: 512)
        XCTAssertEqual(propertyLine("Ti,G" + getter), "@property (getter=\(getter)) int value;")
        let setter = String(repeating: "s", count: 511) + ":"
        XCTAssertEqual(propertyLine("Ti,S" + setter), "@property (setter=\(setter)) int value;")
        assertRefused("Ti,G" + getter + "g")
        assertRefused("Ti,S" + String(setter.dropLast()) + "s:")
    }

    func testSupportedUnicodeAndUnderscoreRemainExact() {
        let composed = propertyLine("Ti,G_\u{e9}tat2,S_\u{e9}crire2:")
        let composedExpected = "@property (getter=_\u{e9}tat2, setter=_\u{e9}crire2:) int value;"
        XCTAssertEqual(Array(composed.utf8), Array(composedExpected.utf8))

        let decomposed = propertyLine("Ti,G_e\u{301}tat2,S_e\u{301}crire2:")
        let decomposedExpected = "@property (getter=_e\u{301}tat2, setter=_e\u{301}crire2:) int value;"
        XCTAssertEqual(Array(decomposed.utf8), Array(decomposedExpected.utf8))
    }

    func testIndependentValidNeighborSurvivesRefusedProperty() {
        let cls = ObjCClass(name: "Sample", superclassName: nil, adoptedProtocols: [], classMethods: [],
                            instanceMethods: [], ivars: [], properties: [
                                ObjCProperty(name: "bad", attributes: "Ti,Gbad:"),
                                ObjCProperty(name: "good", attributes: "Ti,GreadGood")
                            ])
        let output = ObjectiveCHeaderRenderer.render(classes: [cls])
        XCTAssertEqual(output.components(separatedBy: "@property").count - 1, 1)
        XCTAssertTrue(output.contains("@property (getter=readGood) int good;"))
        XCTAssertTrue(output.contains("name=\"bad\""))
    }
}
