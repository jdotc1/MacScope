import XCTest
@testable import MacScope

final class ObjCTypeEncodingBoundsTests: XCTestCase {
    private func signature(_ encoding: String, selector: String = "first:second:") -> String {
        ObjCTypeEncoding.methodSignature(ObjCMethod(selector: selector, typeEncoding: encoding, isClassMethod: false))
    }

    func testLeadingTokenDoesNotRequireWholeMethodConsumption() {
        XCTAssertEqual(ObjCTypeEncoding.decode("i24@0:8"), "int")
        XCTAssertEqual(ObjCTypeEncoding.decode("@?16@0:8"), "id")
        XCTAssertEqual(ObjCTypeEncoding.decode("^@"), "id *")
    }
    func testPrimitiveConstAndQuotedObjectRemainUseful() {
        XCTAssertEqual(ObjCTypeEncoding.decode("r*"), "const char *")
        XCTAssertEqual(ObjCTypeEncoding.decode("@\"NSString\""), "NSString *")
        XCTAssertEqual(ObjCTypeEncoding.decode("Q"), "unsigned long long")
    }
    func testMissingAndUnknownTokensAreNotPointerChildren() {
        for input in ["", "?", "^", "r", "^^?", "^r", "[2?]"] {
            XCTAssertEqual(ObjCTypeEncoding.decode(input), "id", input)
        }
    }
    func testArrayRequiresExtentElementAndClosingDelimiter() {
        for input in ["[i]", "[2]", "[2i", "[2^]", "[2[3i]", "[2i)"] {
            XCTAssertEqual(ObjCTypeEncoding.decode(input), "id", input)
        }
    }
    func testMultidimensionalOrderAndPointerDeclarationPreserved() {
        let type = ObjCTypeEncoding.decode("[2[3^i]]")
        XCTAssertEqual(type, "int *[2][3]")
        XCTAssertEqual(ObjCTypeEncoding.declaration(type: type, name: "matrix"), "int *matrix[2][3]")
    }
    func testZeroAndLeadingZeroExtentsRetainedWithoutAllocationByExtent() {
        XCTAssertEqual(ObjCTypeEncoding.decode("[0i]"), "int[0]")
        XCTAssertEqual(ObjCTypeEncoding.decode("[003i]"), "int[003]")
        XCTAssertEqual(ObjCTypeEncoding.decode("[18446744073709551615i]"), "int[18446744073709551615]")
        XCTAssertEqual(ObjCTypeEncoding.decode("b0"), "unsigned int")
    }
    func testNumericOverflowAndOverlongZeroFieldsRefuse() {
        for input in ["[18446744073709551616i]", "[000000000000000000000i]", "b18446744073709551616", "b", "b000000000000000000000"] {
            XCTAssertEqual(ObjCTypeEncoding.decode(input), "id", input)
        }
    }
    func testNonASCIINumericFieldsRefuse() {
        for input in ["[٢i]", "[２i]", "[²i]", "b٢", "b２", "b²"] {
            XCTAssertEqual(ObjCTypeEncoding.decode(input), "id", input)
        }
    }
    func testUnterminatedQuotesRefuseWithoutDecoratingChildren() {
        for input in ["@\"Foo", "^@\"Foo", "{Foo=\"field}", "{Foo=\"field\\\"}"] {
            XCTAssertEqual(ObjCTypeEncoding.decode(input), "id", input)
        }
    }
    func testMixedAggregateDelimitersAndQuotedDelimiters() {
        XCTAssertEqual(ObjCTypeEncoding.decode("{Outer=\"[ignored}]\"(Union=i[2{Inner=dd}])}"), "Outer")
        XCTAssertEqual(ObjCTypeEncoding.decode("{?=i}"), "void")
        XCTAssertEqual(ObjCTypeEncoding.decode("(=i)"), "void")
        for input in ["{Outer=(Inner=i]}", "{Outer=[2i)}", "{Outer={Inner=i}", "{Outer=i"] {
            XCTAssertEqual(ObjCTypeEncoding.decode(input), "id", input)
        }
    }
    func testValidMethodOffsetsAndCompletePrefix() {
        XCTAssertEqual(signature("v32@0:8i16Q24"), "- (void)first:(int)arg0 second:(unsigned long long)arg1;")
        XCTAssertEqual(signature("v32@0:8i16[2^]Q24"), "- (void)first:(int)arg0 second:(id)arg1;")
    }
    func testMalformedMethodTokenDoesNotResynchronizeIntoArguments() {
        XCTAssertEqual(signature("v24@0:8^?i16"), "- (void)first:(id)arg0 second:(id)arg1;")
        XCTAssertEqual(signature("v24@0:8@\"unterminatedi16"), "- (void)first:(id)arg0 second:(id)arg1;")
    }
    func testBadOffsetStopsTailInsteadOfManufacturingArguments() {
        XCTAssertEqual(signature("v18446744073709551616@0:8i16"), "- (void)first:(id)arg0 second:(id)arg1;")
        XCTAssertEqual(signature("v٢@0:8i16"), "- (void)first:(id)arg0 second:(id)arg1;")
        XCTAssertEqual(signature("1234"), "- (id)first:(id)arg0 second:(id)arg1;")
    }
    func testInputByteBoundaryAndBoundedQualifierScan() {
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "n", count: 8191) + "i"), "int")
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "n", count: 8192) + "i"), "id")
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "n", count: 8192)), "id")
    }
    func testPointerDepthBoundary() {
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "^", count: 31) + "i"), "int " + String(repeating: "*", count: 31))
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "^", count: 32) + "i"), "id")
    }
    func testAggregateDepthBoundary() {
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "{T=", count: 32) + "i" + String(repeating: "}", count: 32)), "T")
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "{T=", count: 33) + "i" + String(repeating: "}", count: 33)), "id")
    }
    func testCumulativeRenderedOutputBoundary() {
        // Object rendering is charged for its construction and final token, not only its last copy.
        let allowed = String(repeating: "A", count: 4094)
        XCTAssertEqual(ObjCTypeEncoding.decode("@\"" + allowed + "\""), allowed + " *")
        XCTAssertEqual(ObjCTypeEncoding.decode("@\"" + allowed + "A\""), "id")
    }
    func testSharedWorkBudgetAtAndBeyondBoundary() {
        let name = String(repeating: "A", count: 4094)
        let token = "@\"" + name + "\""
        // 8191 consumed bytes + 8192 rendered bytes + one token-entry charge.
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "n", count: 4094) + token), name + " *")
        // Still within the input/output caps; the additional qualifier exhausts shared work.
        XCTAssertEqual(ObjCTypeEncoding.decode(String(repeating: "n", count: 4095) + token), "id")
    }
    func testMethodTokenLimitKeepsPositions() {
        let selector = String(repeating: "arg:", count: 126)
        let result = signature("v@:" + String(repeating: "i", count: 126), selector: selector)
        XCTAssertTrue(result.contains("arg:(int)arg124"))
        XCTAssertTrue(result.contains("arg:(id)arg125"))
    }
    func testSharedOutputBudgetAcrossMethodTokens() {
        let object = "@\"" + String(repeating: "A", count: 2046) + "\""
        let result = signature("v@:" + object + object + "i")
        XCTAssertTrue(result.contains("first:(" + String(repeating: "A", count: 2046) + " *)arg0"))
        XCTAssertTrue(result.contains("second:(id)arg1"))
    }
    func testDeclarationSuffixHelperBoundsAndASCIIDigits() {
        XCTAssertEqual(ObjCTypeEncoding.declaration(type: String(repeating: "A", count: 8193), name: "x"), "id x")
        XCTAssertEqual(ObjCTypeEncoding.declaration(type: "int[２]", name: "x"), "int[２] x")
        XCTAssertEqual(ObjCTypeEncoding.declaration(type: "int[2][3]", name: "x"), "int x[2][3]")
    }
    func testInvalidModelTypesStayFallbackInActualHeaderRenderer() {
        let cls = ObjCClass(name: "Sample", superclassName: nil, adoptedProtocols: [], classMethods: [],
                            instanceMethods: [ObjCMethod(selector: "set:", typeEncoding: "v@:^?i", isClassMethod: false)],
                            ivars: [ObjCIvar(name: "_broken", typeEncoding: "[2^")],
                            properties: [ObjCProperty(name: "broken", attributes: "T^?")])
        let output = ObjectiveCHeaderRenderer.render(classes: [cls])
        XCTAssertTrue(output.contains("id _broken;"))
        XCTAssertTrue(output.contains("id broken;"))
        XCTAssertTrue(output.contains("- (void)set:(id)arg0;"))
        XCTAssertFalse(output.contains("id *"))
    }
}
