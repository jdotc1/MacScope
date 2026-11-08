import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeDeclarationTests: XCTestCase {
    func testDC01FreeDeclaration() throws {
        let value = try XCTUnwrap(parseThrowingDeclaration("_$s4Demo5parseyS2iKF"))
        XCTAssertEqual(value.symbol, String("_$s4Demo5parseyS2iKF")); XCTAssertEqual(value.module, String("Demo"))
        XCTAssertEqual(value.callableKind, String("free_function")); XCTAssertNil(value.typeName)
        XCTAssertEqual(value.functionName, String("parse")); XCTAssertEqual(value.parameterTypes, [String](arrayLiteral: "Swift.Int")); XCTAssertEqual(value.resultType, String("Swift.Int"))
        let expected: SwiftOutcomeJSON = .object(["module": .string("Demo"), "name": .string("parse"), "parameters": .array([.string("Swift.Int")]), "result": .string("Swift.Int"), "convention": .string("swift_sync_untyped_throws"), "error_register": .string("x21"), "source": .string("exact_external_symbol_grammar")])
        XCTAssertEqual(value.record(), expected)
    }
    func testDC02Signatures() throws {
        let cases: [(String, [String], String)] = [("yySiKF", ["Swift.Int"], "Swift.Void"), ("SiyKF", [], "Swift.Int"), ("yyKF", [], "Swift.Void")]
        for (suffix, parameters, result) in cases {
            let value = try XCTUnwrap(parseThrowingDeclaration("_$s4Demo5parse" + suffix))
            XCTAssertEqual(value.parameterTypes, parameters); XCTAssertEqual(value.resultType, result)
        }
    }
    func testDC03NoUnderscore() throws {
        XCTAssertEqual(try XCTUnwrap(parseThrowingDeclaration("$s4Demo5parseyyKF")).symbol, String("$s4Demo5parseyyKF"))
    }
    func testDC04RejectSyntax() {
        let cases: [String] = ["_$s4Demo5parseyS2iF", "_$s4Demo5parseyS2iYaKF", "_$s4Demo5parseyS2iAA5FaultOYKF", "_$s4Demo5parseyS2iKFTA", "_$s4Demo5parseyS2iKF.llvm.1", "_$s04Demo5parseyS2iKF", "_$s4Dem5parseyS2iKF", "ordinary_c_function", "_$s4D\u{e9}m5parseyyKF", "", "_$s", "_$s4Demo", "_$s4Demo5pars"]
        for text in cases { XCTAssertNil(parseThrowingDeclaration(text), text) }
    }
    func testDC05MethodOptIn() throws {
        let symbol: String = "_$s4Demo5PointV3sumyS2iKF"
        XCTAssertNil(parseThrowingDeclaration(symbol))
        let value = try XCTUnwrap(parseThrowingDeclaration(symbol, allowMethods: true))
        XCTAssertEqual(value.callableKind, String("struct_instance_method")); XCTAssertEqual(value.typeName, String("Point")); XCTAssertEqual(value.functionName, String("sum"))
        XCTAssertEqual(value.parameterTypes, [String](arrayLiteral: "Swift.Int")); XCTAssertEqual(value.resultType, String("Swift.Int"))
        let expected: SwiftOutcomeJSON = .object(["module": .string("Demo"), "name": .string("sum"), "parameters": .array([.string("Swift.Int")]), "result": .string("Swift.Int"), "convention": .string("swift_sync_untyped_throws"), "error_register": .string("x21"), "source": .string("exact_external_symbol_grammar"), "callable_kind": .string("struct_instance_method"), "type_name": .string("Point"), "declaration_model_version": .string("swift-throwing-declarations-v1")])
        XCTAssertEqual(value.record(), expected)
    }
    func testDC06VoidMethodRefused() { XCTAssertNil(parseThrowingDeclaration("_$s4Demo5PointV3sumyyKF", allowMethods: true)) }
    func testDC07IdentifierBound() throws {
        XCTAssertEqual(try XCTUnwrap(parseThrowingDeclaration("_$s4Demo128" + String(repeating: "a", count: 128) + "yyKF")).functionName.count, Int(128))
        XCTAssertNil(parseThrowingDeclaration("_$s4Demo129" + String(repeating: "a", count: 129) + "yyKF"))
    }

    func testTP4PortableVoidDeclarations() throws {
        XCTAssertEqual(try XCTUnwrap(parseThrowingDeclaration("_$s4Demo8validateyyKF")).resultType,String("Swift.Void"))
        let argument = try XCTUnwrap(parseThrowingDeclaration("_$s4Demo8validateyySiKF"))
        XCTAssertEqual(argument.parameterTypes,[String("Swift.Int")]); XCTAssertEqual(argument.resultType,String("Swift.Void"))
        for symbol in ["_$s4Demo8validateyyF","_$s4Demo8validateyyYaKF","_$s4Demo8validateSSyKF"] { XCTAssertNil(parseThrowingDeclaration(symbol)) }
    }

}
#endif
