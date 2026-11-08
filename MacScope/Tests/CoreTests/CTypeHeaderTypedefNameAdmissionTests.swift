import Foundation
import XCTest
@testable import MacScope

final class CTypeHeaderTypedefNameAdmissionTests: XCTestCase {
    private let missingBody = "Skipped a struct/union without a `{ … }` body."

    private func refusal(_ name: String) -> String {
        "Skipped reserved typedef name `\(name)`."
    }

    private func catalog(_ result: CTypeHeaderParser.Result) -> [String: TypeDefinition] {
        Dictionary(result.types.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func assertRefused(_ declaration: String, name: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        let result = CTypeHeaderParser.parse(declaration + " typedef int After;")
        let types = catalog(result)
        XCTAssertNil(types[name], declaration, file: file, line: line)
        XCTAssertEqual(result.types.map(\.name), ["After"], declaration, file: file, line: line)
        XCTAssertEqual(types["After"]?.fields.first?.type, "int32_t", file: file, line: line)
        XCTAssertEqual(result.diagnostics, [refusal(name)], declaration, file: file, line: line)
    }

    // Plain path, SPEC 2: fails before the fix.
    func testPlainPrimitiveKeywordNamesRefused() {
        assertRefused("typedef int int;", name: "int")
        assertRefused("typedef unsigned int;", name: "int")
    }

    // Plain path, SPEC 1-3: fails before the fix; needs 858.
    func testPlainExtendedNameAndDecorationsRefused() {
        for declaration in [
            "typedef int __int128;",
            "typedef unsigned __int128;",
            "typedef int *__int128;",
            "typedef int __int128[4];",
            "typedef int __int128 __attribute__((packed));"
        ] {
            assertRefused(declaration, name: "__int128")
        }
    }

    // Plain path, SPEC 4: fails before the fix; exact original vocabulary, minus the attribute introducer.
    func testOriginalReservedPlainNamesRefused() {
        let words = [
            "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
            "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
            "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
            "volatile", "while", "bool", "_Bool", "_Atomic", "_Alignas", "_Alignof", "_Complex", "_Imaginary",
            "_Generic", "_Noreturn", "_Static_assert", "_Thread_local", "__restrict", "__restrict__",
            "__const", "__volatile", "__volatile__", "__inline", "__inline__", "__signed", "__signed__",
            "__complex__", "__extension__", "typeof", "__typeof", "__typeof__", "_Nonnull", "_Nullable",
            "_Null_unspecified", "_Nullable_result", "__nonnull", "__nullable", "__null_unspecified",
            "__attribute", "__declspec", "asm", "__asm", "__asm__",
        ]
        XCTAssertEqual(words.count, 71)
        XCTAssertEqual(Set(words).count, 71)
        for word in words {
            assertRefused("typedef int \(word);", name: word)
        }
    }

    // Plain path, SPEC 4: fails before the fix; needs 858 for these two exact words.
    func testAdditionalReservedPlainNamesRefused() {
        for word in ["__int128", "__const__"] {
            assertRefused("typedef int \(word);", name: word)
        }
    }

    // Plain path, SPEC 4: positive control (passes before).
    func testMalformedAttributeNameKeepsExistingDiagnostics() {
        let result = CTypeHeaderParser.parse("typedef int __attribute__; typedef int After;")
        XCTAssertEqual(result.types.map(\.name), ["After"])
        XCTAssertEqual(result.types.first?.fields.first?.type, "int32_t")
        XCTAssertEqual(result.diagnostics, [
            "Ignored malformed `__attribute__`.",
            "Skipped a malformed `typedef` (need `<type> <alias>;`)."
        ])
    }

    // Plain path, SPEC 5: fails before the fix.
    func testBooleanAliasPolicyRefusesAllThreeForms() {
        assertRefused("typedef _Bool bool;", name: "bool")
        assertRefused("typedef bool _Bool;", name: "_Bool")
        assertRefused("typedef int bool;", name: "bool")
        let result = CTypeHeaderParser.parse("typedef int bool; struct S { bool x; };")
        XCTAssertEqual(catalog(result)["S"]?.fields.first?.type, "_Bool")
        XCTAssertEqual(result.diagnostics, [refusal("bool")])
    }

    // Function-pointer path, SPEC 6: fails before the fix; needs 858 for __int128.
    func testFunctionPointerTypedefNamesRefused() {
        assertRefused("typedef int (*__int128)(int);", name: "__int128")
        assertRefused("typedef void (*const)(void);", name: "const")
    }

    // Member path, SPEC 7: positive control (passes before); no dependency on the added vocabulary.
    func testReservedSpellingMembersRemainUnchanged() {
        let result = CTypeHeaderParser.parse(
            "struct S { int __int128; int (*__const__)(int); }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["S"]?.fields.map(\.name), ["__int128", "__const__"])
        XCTAssertEqual(types["S"]?.fields.first?.type, "int32_t")
        XCTAssertEqual(types["S"]?.fields.last?.type, "int32_t *")
        XCTAssertEqual(types["S"]?.fields.last?.declaratorSemanticsV1, .functionPointerCarrier)
        XCTAssertEqual(types["S"]?.fields.last?.functionPointerSignatureV1?.returnType, "int32_t")
        XCTAssertEqual(types["S"]?.fields.last?.functionPointerSignatureV1?.parameters.map(\.type), ["int32_t"])
        XCTAssertEqual(types["After"]?.fields.first?.type, "int32_t")
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // Record path, SPEC 8: fails before the fix; needs 858 for __int128.
    func testRecordAliasesRefuseTheWholeStatement() {
        assertRefused("typedef struct { int x; } __int128;", name: "__int128")
        assertRefused("typedef union { int x; } void;", name: "void")
        assertRefused("typedef struct T { int x; } __int128;", name: "__int128")
        let result = CTypeHeaderParser.parse("typedef struct T { int x; } __int128; typedef int After;")
        XCTAssertNil(catalog(result)["T"])
        XCTAssertEqual(result.diagnostics, [refusal("__int128")])
    }

    // Enum path, SPEC 9: fails before the fix; needs 858 for __int128.
    func testEnumAliasesRefuseTheWholeStatement() {
        assertRefused("typedef enum { X } __int128;", name: "__int128")
        assertRefused("typedef enum E { X } void;", name: "void")
        let result = CTypeHeaderParser.parse("typedef enum E { X } void; typedef int After;")
        XCTAssertNil(catalog(result)["E"])
        XCTAssertNil(catalog(result)["X"])
        XCTAssertEqual(result.diagnostics, [refusal("void")])
    }

    // Record path, SPEC 10: fails before the fix.
    func testQualifierAfterBodyIsRefusedWithoutRecoveringLaterAlias() {
        assertRefused("typedef struct { int x; } const A;", name: "const")
        let result = CTypeHeaderParser.parse("typedef struct { int x; } const A;")
        XCTAssertNil(catalog(result)["A"])
        XCTAssertEqual(result.diagnostics, [refusal("const")])
    }

    // Plain comma path, SPEC 11(a): positive control (passes before); no dependency on 858.
    func testPlainCommaRemainsUnsupported() {
        let result = CTypeHeaderParser.parse("typedef int __int128, After2; typedef int After;")
        XCTAssertEqual(result.types.map(\.name), ["After"])
        XCTAssertEqual(result.types.first?.fields.first?.type, "int32_t")
        XCTAssertEqual(result.diagnostics, ["Skipped an unsupported `typedef` form."])
    }

    // Record path, SPEC 11(b): positive control (passes before); the ignored suffix needs no vocabulary change.
    func testRecordCommaKeepsOnlyTheFirstAlias() {
        let result = CTypeHeaderParser.parse(
            "typedef struct { int x; } A, __int128; typedef int After;")
        XCTAssertEqual(result.types.map(\.name), ["A", "After"])
        XCTAssertEqual(catalog(result)["A"]?.kind, .struct)
        XCTAssertEqual(catalog(result)["A"]?.fields.first?.type, "int32_t")
        XCTAssertEqual(catalog(result)["After"]?.fields.first?.type, "int32_t")
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // Record path, SPEC 11(c): fails before the fix; needs 858.
    func testReservedFirstRecordCommaAliasIsRefused() {
        assertRefused("typedef struct { int x; } __int128, A;", name: "__int128")
    }

    // Tag paths, SPEC 13: positive control (passes before); names are not typedef aliases.
    func testReservedSpellingTagsRemainUnchanged() {
        let result = CTypeHeaderParser.parse(
            "struct __int128 { int x; }; union void { int y; }; enum const { X }; typedef int After;")
        XCTAssertEqual(result.types.map(\.name), ["__int128", "void", "const", "After"])
        XCTAssertEqual(result.types.map(\.kind), [.struct, .union, .enum, .typedef])
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // Plain/tag interaction, SPEC 14: fails before the fix; needs 858.
    func testRefusedAliasDoesNotReserveTheLaterTagName() {
        let result = CTypeHeaderParser.parse(
            "typedef int __int128; struct __int128 { int x; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["__int128"]?.kind, .struct)
        XCTAssertEqual(types["__int128"]?.fields.first?.name, "x")
        XCTAssertEqual(types["__int128"]?.fields.first?.type, "int32_t")
        XCTAssertEqual(result.types.map(\.name), ["__int128", "After"])
        XCTAssertEqual(result.diagnostics, [refusal("__int128")])
    }

    // Prototype context, SPEC 15(a): fails before the fix.
    func testPrototypeIntReturnCannotBeReboundByMissingDeclarator() {
        let result = CTypeHeaderParser.parse("typedef unsigned int; int f(void);")
        XCTAssertEqual(result.prototypes.first?.signature.returnType, "int32_t")
        XCTAssertEqual(result.prototypes.map(\.name), ["f"])
        XCTAssertTrue(result.types.isEmpty)
        XCTAssertEqual(result.diagnostics, [refusal("int")])
    }

    // Prototype context, SPEC 15(b): fails before the fix; needs 858.
    func testPrototypeInt128ReturnCannotBeRebound() {
        let result = CTypeHeaderParser.parse("typedef int __int128; __int128 g(void);")
        XCTAssertEqual(result.prototypes.first?.signature.returnType, "__int128")
        XCTAssertEqual(result.prototypes.map(\.name), ["g"])
        XCTAssertTrue(result.types.isEmpty)
        XCTAssertEqual(result.diagnostics, [refusal("__int128")])
    }

    // Prototype context, SPEC 15: fails before the fix; exercise all context dictionaries.
    func testPrototypeOtherTypedefShapesCannotShadowPrimitiveInt() {
        for declaration in [
            "typedef void (*int)(void);",
            "typedef short int[2];",
            "typedef struct { short x; } int;",
            "typedef struct T { short x; } int;",
            "typedef enum { X } int;",
            "typedef enum E { X } int;"
        ] {
            let result = CTypeHeaderParser.parse(declaration + " int f(void);")
            XCTAssertEqual(result.prototypes.first?.signature.returnType, "int32_t", declaration)
            XCTAssertEqual(result.prototypes.map(\.name), ["f"], declaration)
            XCTAssertTrue(result.types.isEmpty, declaration)
            XCTAssertEqual(result.diagnostics, [refusal("int")], declaration)
        }
        let bodyless = CTypeHeaderParser.parse("typedef struct T *int; int f(void);")
        XCTAssertEqual(bodyless.prototypes.first?.signature.returnType, "int32_t")
        XCTAssertTrue(bodyless.types.isEmpty)
        XCTAssertEqual(bodyless.diagnostics, [missingBody])
    }

    // Plain path, SPEC 16: positive control (passes before); exact words, not prefixes.
    func testNearKeywordNamesKeepTypesAndLayout() {
        let result = CTypeHeaderParser.parse("""
            typedef __int128 __int128_t; typedef unsigned __int128 uint128_t;
            typedef signed __int128 int128_t; typedef int int_t;
            typedef unsigned unsigned_t; typedef int BOOL; typedef int Bool; typedef int After;
            """)
        let types = catalog(result)
        XCTAssertEqual(result.types.map(\.name),
                       ["__int128_t", "uint128_t", "int128_t", "int_t", "unsigned_t", "BOOL", "Bool", "After"])
        for name in ["__int128_t", "int128_t"] {
            XCTAssertEqual(types[name]?.fields.first?.type, "__int128")
        }
        XCTAssertEqual(types["uint128_t"]?.fields.first?.type, "unsigned __int128")
        for name in ["int_t", "BOOL", "Bool", "After"] {
            XCTAssertEqual(types[name]?.fields.first?.type, "int32_t")
        }
        XCTAssertEqual(types["unsigned_t"]?.fields.first?.type, "uint32_t")
        for name in ["__int128_t", "uint128_t", "int128_t"] {
            XCTAssertEqual(TypeDefinition.size(ofType: name, in: types), 16)
            XCTAssertEqual(TypeDefinition.alignment(ofType: name, in: types), 16)
        }
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // All admitted paths, SPEC 17: positive control (passes before).
    func testLibjpegStyleNamesRemainAdmitted() {
        let result = CTypeHeaderParser.parse("""
            typedef unsigned char JSAMPLE; typedef int boolean;
            typedef struct jpeg_common_struct *j_common_ptr;
            typedef int (*jpeg_marker_parser_method)(int cinfo);
            typedef struct { int x; } JQUANT_TBL;
            typedef enum { JCS_UNKNOWN } J_COLOR_SPACE; typedef int After;
            """)
        let types = catalog(result)
        XCTAssertEqual(result.types.map(\.name),
                       ["JSAMPLE", "boolean", "j_common_ptr", "jpeg_marker_parser_method",
                        "JQUANT_TBL", "J_COLOR_SPACE", "After"])
        XCTAssertEqual(types["JSAMPLE"]?.fields.first?.type, "uint8_t")
        XCTAssertEqual(types["boolean"]?.fields.first?.type, "int32_t")
        XCTAssertEqual(types["j_common_ptr"]?.fields.first?.type, "struct jpeg_common_struct *")
        XCTAssertEqual(types["jpeg_marker_parser_method"]?.fields.first?.type, "int32_t *")
        XCTAssertEqual(types["jpeg_marker_parser_method"]?.fields.first?.functionPointerSignatureV1?.parameters.first?.name, "cinfo")
        XCTAssertEqual(types["JQUANT_TBL"]?.kind, .struct)
        XCTAssertEqual(types["J_COLOR_SPACE"]?.kind, .enum)
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // Four admission paths, SPEC 19/27: fails before the fix; needs 858.
    func testRecoveryAndIdentifierAllocationSkipRefusedStatements() {
        let source = """
            typedef int __int128; typedef int (*__const__)(int);
            typedef struct { int x; } int; typedef enum { X } void;
            typedef unsigned __int128 uint128_t; typedef int After;
            """
        let first = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let second = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        var calls = 0
        let result = CTypeHeaderParser.parse(source, idProvider: {
            calls += 1
            return calls == 1 ? first : second
        })
        XCTAssertEqual(result.types.map(\.name), ["uint128_t", "After"])
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(result.types.map(\.id), [first, second])
        XCTAssertEqual(result.diagnostics, ["__int128", "__const__", "int", "void"].map(refusal))
        let types = catalog(result)
        XCTAssertEqual(types["uint128_t"]?.fields.first?.type, "unsigned __int128")
        XCTAssertEqual(TypeDefinition.size(ofType: "uint128_t", in: types), 16)
        XCTAssertEqual(types["After"]?.fields.first?.type, "int32_t")
    }

    // Bodyless path, SPEC 12(b): positive control (passes before).
    func testBodylessReservedNameKeepsSingleMissingBodyDiagnostic() {
        let result = CTypeHeaderParser.parse("typedef struct T *int; typedef int After;")
        XCTAssertEqual(result.types.map(\.name), ["After"])
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // Non-reserved prototype context, SPEC 15/21: positive control (passes before).
    func testNonreservedContextRemainsIndependentOfCatalogRefusal() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct A { int x; }; void f(A p); typedef int After;")
        XCTAssertEqual(result.prototypes.first?.signature.returnType, "void")
        XCTAssertEqual(result.prototypes.first?.signature.args.map(\.type), ["struct T *"])
        XCTAssertEqual(catalog(result)["A"]?.kind, .struct)
        XCTAssertEqual(result.diagnostics, [missingBody])
    }
}
