import Foundation
import XCTest
@testable import MacScope

final class CTypeHeaderBodylessRecordTypedefTests: XCTestCase {
    private let missingBody = "Skipped a struct/union without a `{ … }` body."

    private func fields(_ pairs: [(String, String)]) -> [FieldDef] {
        pairs.map { FieldDef(name: $0.0, type: $0.1, declaratorSemanticsV1: .ordinary) }
    }

    private func catalog(_ result: CTypeHeaderParser.Result) -> [String: TypeDefinition] {
        Dictionary(result.types.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func assertPointer(_ source: String, alias: String = "A", target: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        let result = CTypeHeaderParser.parse(source)
        let types = catalog(result)
        XCTAssertTrue(result.diagnostics.isEmpty, result.diagnostics.joined(separator: "\n"), file: file, line: line)
        XCTAssertEqual(types[alias]?.kind, .typedef, file: file, line: line)
        XCTAssertEqual(types[alias]?.fields, [FieldDef(name: alias, type: target, declaratorSemanticsV1: .ordinary)], file: file, line: line)
        XCTAssertEqual(TypeDefinition.size(ofType: alias, in: types), 8, file: file, line: line)
        XCTAssertEqual(TypeDefinition.alignment(ofType: alias, in: types), 8, file: file, line: line)
        let resolver = TypeAtlasDarwinARM64LayoutResolver(catalog: types)
        XCTAssertEqual(DarwinARM64ParameterBinder.returnLocation(for: alias, resolver: resolver),
                       .single(.gpr(index: 0, carrierWidth: 64)), file: file, line: line)
        XCTAssertEqual(DarwinARM64ParameterBinder.bindRich(parameterTypes: [alias], resolver: resolver),
                       [.gpr(index: 0, carrierWidth: 64)], file: file, line: line)
    }

    private func assertRefused(_ declaration: String, alias: String = "A",
                               file: StaticString = #filePath, line: UInt = #line) {
        let result = CTypeHeaderParser.parse(declaration + " typedef int After;")
        let types = catalog(result)
        XCTAssertNil(types[alias], file: file, line: line)
        XCTAssertEqual(types["After"]?.fields.first?.type, "int32_t", file: file, line: line)
        XCTAssertTrue(result.diagnostics.contains(missingBody), declaration, file: file, line: line)
    }

    // Condition: a single struct pointer typedef has a carrier; reversion loses A and its x0 binding.
    func testStructPointer() {
        assertPointer("typedef struct T *A;", target: "struct T *")
    }

    // Condition: a union pointer needs no union body; reversion loses A and its carrier.
    func testUnionPointer() {
        assertPointer("typedef union T *A;", target: "union T *")
    }

    // Condition: multiple pointer levels survive exactly; reversion emits no typedef.
    func testDoublePointer() {
        assertPointer("typedef struct T **A;", target: "struct T **")
    }

    // Condition: the existing leading-const plain path stays unchanged; reversion still stores T *.
    func testLeadingConstPointerUsesExistingPlainPath() {
        assertPointer("typedef const struct T *A;", target: "T *")
    }

    // Condition: an incomplete by-value typedef supplies no layout; reversion keeps the same refusal.
    func testIncompleteByValueReturnParameterAndMemberRemainUnbound() {
        let result = CTypeHeaderParser.parse("typedef struct T A; struct Holder { A value; };")
        let types = catalog(result)
        XCTAssertNil(types["A"])
        XCTAssertEqual(result.diagnostics, [missingBody])
        XCTAssertNil(TypeDefinition.size(ofType: "A", in: types))
        let resolver = TypeAtlasDarwinARM64LayoutResolver(catalog: types)
        XCTAssertNil(resolver.resolveLayout(ofType: "Holder"))
        XCTAssertEqual(DarwinARM64ParameterBinder.returnLocation(for: "A", resolver: resolver), .unbound(reason: .unsupportedType("A")))
        XCTAssertEqual(DarwinARM64ParameterBinder.bindRich(parameterTypes: ["A", "int"], resolver: resolver),
                       [.unbound(reason: .unsupportedType("A")), .unbound(reason: .dependentOnUnsupportedEarlierParameter)])
    }

    // Condition: a pointer alias does not create a by-value pointee layout; reversion instead loses the pointer alias.
    func testPointerDoesNotCompleteRecord() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct Holder { struct T value; };")
        let types = catalog(result)
        XCTAssertNotNil(types["A"])
        XCTAssertNil(types["T"])
        let resolver = TypeAtlasDarwinARM64LayoutResolver(catalog: types)
        XCTAssertNil(resolver.resolveLayout(ofType: "struct T"))
        XCTAssertNil(resolver.resolveLayout(ofType: "Holder"))
    }

    // Condition: later tag completion cannot be shadowed by a distinct pointer alias; reversion loses A only.
    func testPointerAliasBeforeLaterRecordBody() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct T { int value; };")
        let types = catalog(result)
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertEqual(types["T"]?.kind, .struct)
        XCTAssertEqual(types["A"]?.fields.first?.type, "struct T *")
        XCTAssertEqual(TypeDefinition.size(ofType: "T", in: types), 4)
        XCTAssertEqual(TypeAtlasDarwinARM64LayoutResolver(catalog: types).resolveLayout(ofType: "struct T")?.size, 4)
    }

    // Condition: a by-value alias remains outside this pointer-only admission even after completion; reversion is identical.
    func testByValueAliasBeforeLaterRecordBodyStaysRefused() {
        let result = CTypeHeaderParser.parse("typedef struct T A; struct T { int value; };")
        let types = catalog(result)
        XCTAssertNil(types["A"])
        XCTAssertEqual(types["T"]?.kind, .struct)
        XCTAssertEqual(result.diagnostics, [missingBody])
        XCTAssertNil(TypeAtlasDarwinARM64LayoutResolver(catalog: types).resolveLayout(ofType: "A"))
    }

    // Condition: an identity alias cannot reserve the later tag name; reversion preserves this conservative refusal.
    func testAliasEqualsTagDoesNotShadowLaterBody() {
        let result = CTypeHeaderParser.parse("typedef struct T T; struct T { int value; };")
        let types = catalog(result)
        XCTAssertEqual(result.types.count, 1)
        XCTAssertEqual(types["T"]?.kind, .struct)
        XCTAssertEqual(TypeDefinition.size(ofType: "T", in: types), 4)
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // Condition: a same-name pointer alias cannot shadow its tag in the flat atlas; reversion keeps the refusal.
    func testPointerAliasEqualsTagStaysRefused() {
        let result = CTypeHeaderParser.parse("typedef struct T *T; struct T { int value; };")
        XCTAssertEqual(result.types.map(\.kind), [.struct])
        XCTAssertEqual(result.types.map(\.name), ["T"])
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // Condition: tagged body typedefs retain their old alias-only record representation; reversion has identical fields and diagnostics.
    func testTaggedBodyUnchanged() {
        let result = CTypeHeaderParser.parse("typedef struct T { int value; } A;")
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertEqual(result.types.map(\.name), ["A"])
        XCTAssertEqual(result.types.first?.kind, .struct)
        XCTAssertEqual(result.types.first?.fields, [FieldDef(name: "value", type: "int32_t", declaratorSemanticsV1: .ordinary)])
    }

    // Condition: anonymous body typedefs retain the existing record representation; reversion is identical.
    func testAnonymousBodyUnchanged() {
        let result = CTypeHeaderParser.parse("typedef struct { int value; } A;")
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertEqual(result.types.map(\.name), ["A"])
        XCTAssertEqual(result.types.first?.kind, .struct)
        XCTAssertEqual(result.types.first?.fields, [FieldDef(name: "value", type: "int32_t", declaratorSemanticsV1: .ordinary)])
    }

    // Condition: a missing alias is not inferred from the tag; reversion retains the same diagnostic.
    func testMissingAliasRefused() { assertRefused("typedef struct T *;") }

    // Condition: a missing tag is not inferred from the alias; reversion retains the refusal.
    func testMissingTagRefused() { assertRefused("typedef struct *A;") }

    // Condition: bodyless function-pointer declarators are not data pointers; reversion retains the refusal.
    func testFunctionPointerRefused() { assertRefused("typedef struct T (*A)(void);") }

    // Condition: an array declarator is not silently truncated to a pointer; reversion retains the refusal.
    func testArrayAliasRefused() { assertRefused("typedef struct T *A[2];") }

    // Condition: multiple aliases are not partially imported; reversion retains the refusal.
    func testMultipleAliasesRefused() { assertRefused("typedef struct T *A, *B;") }

    // Condition: pointer qualifiers outside the narrow declarator grammar stay refused; reversion retains the refusal.
    func testPointerQualifierRefused() { assertRefused("typedef struct T *const A;") }

    // Condition: attributed bodyless aliases are not given an invented layout; reversion retains the refusal.
    func testAttributedPointerRefused() { assertRefused("typedef struct __attribute__((aligned(16))) T *A;") }

    // Condition: absence of the terminating semicolon cannot emit a partial alias; reversion retains the refusal.
    func testMissingSemicolonRefused() {
        let result = CTypeHeaderParser.parse("typedef struct T *A")
        XCTAssertTrue(result.types.isEmpty)
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // Condition: a duplicate alias cannot replace an earlier definition in this parse; reversion instead diagnoses a missing body.
    func testEarlierAliasWinsInsideParse() {
        let result = CTypeHeaderParser.parse("typedef int A; typedef struct T *A;")
        XCTAssertEqual(result.types.count, 1)
        XCTAssertEqual(result.types.first?.fields.first?.type, "int32_t")
        XCTAssertEqual(result.diagnostics, ["Skipped duplicate type “A” (already defined earlier in this header)."])
    }

    // Condition: a repeated admitted pointer remains first-wins; reversion emits neither pointer alias.
    func testRepeatedPointerAliasIsDiagnosed() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; typedef struct T *A;")
        XCTAssertEqual(result.types.count, 1)
        XCTAssertEqual(result.types.first?.fields.first?.type, "struct T *")
        XCTAssertEqual(result.diagnostics, ["Skipped duplicate type “A” (already defined earlier in this header)."])
    }

    // Condition: an existing catalog definition is never overwritten by import; reversion loses the parsed layout evidence.
    func testHeaderImportPreservesExistingDefinition() throws {
        let existing = try XCTUnwrap(CTypeHeaderParser.parse("typedef int A;").types.first)
        let result = HeaderImportCore.prepare(source: "typedef struct T *A;", typeDefinitions: [existing],
            exports: [], functions: [], importedPrototypes: [:], slot: .primary)
        XCTAssertEqual(result.types, [existing])
        XCTAssertTrue(result.addedNames.isEmpty)
        XCTAssertTrue(result.diagnostics.contains("Skipped “A”: a type with that name already exists in the catalog."))
        XCTAssertEqual(result.headerLayoutDefinitions.first?.fields.first?.type, "struct T *")
    }

    // Condition: an unrelated unresolved name is never rescued by the new typedef; reversion loses A but does not bind Missing.
    func testUnresolvedAliasStaysUnbound() {
        let result = CTypeHeaderParser.parse("typedef struct T *A;")
        XCTAssertEqual(result.types.map(\.name), ["A"])
        let resolver = TypeAtlasDarwinARM64LayoutResolver(catalog: catalog(result))
        XCTAssertEqual(DarwinARM64ParameterBinder.returnLocation(for: "Missing", resolver: resolver), .unbound(reason: .unsupportedType("Missing")))
    }

    // Condition: a pointer-alias member becomes sized without requiring its pointee; reversion makes the member unresolved.
    func testPointerAliasMemberLayout() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct Holder { A pointer; };")
        let types = catalog(result)
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 8)
        XCTAssertEqual(TypeAtlasDarwinARM64LayoutResolver(catalog: types).resolveLayout(ofType: "Holder")?.size, 8)
    }

    // Condition: callback and prototype spellings stay nominal while the atlas gains A; reversion loses only A.
    func testPrototypeAndCallbackSpellingUnchanged() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; A f(A p); struct Hooks { A (*f)(A p); };")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.fields.first?.type, "struct T *")
        XCTAssertEqual(result.prototypes.first?.signature.returnType, "struct T *")
        XCTAssertEqual(result.prototypes.first?.signature.args.map(\.type), ["struct T *"])
        XCTAssertEqual(types["Hooks"]?.fields.first?.functionPointerSignatureV1?.returnType, "struct T *")
        XCTAssertEqual(types["Hooks"]?.fields.first?.functionPointerSignatureV1?.parameters.map(\.type), ["struct T *"])
    }

    // Condition: standalone forward declarations remain a separate unsupported form; reversion preserves their diagnostics.
    func testStandaloneForwardDeclarationUnchanged() {
        let result = CTypeHeaderParser.parse("struct T; union U;")
        XCTAssertTrue(result.types.isEmpty)
        XCTAssertEqual(result.diagnostics, [missingBody, missingBody])
    }

    // Condition: union bodies retain their old kind and fields; reversion is identical.
    func testUnionBodyUnchanged() {
        let result = CTypeHeaderParser.parse("typedef union T { int value; } A;")
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertEqual(result.types.map(\.name), ["A"])
        XCTAssertEqual(result.types.first?.kind, .union)
        XCTAssertEqual(result.types.first?.fields.first?.type, "int32_t")
    }

    // Condition: an identity alias alone does not complete its record; reversion remains unbound.
    func testIdentityAliasAloneStaysUnbound() {
        let result = CTypeHeaderParser.parse("typedef struct T T;")
        XCTAssertTrue(result.types.isEmpty)
        XCTAssertEqual(result.diagnostics, [missingBody])
        XCTAssertNil(TypeAtlasDarwinARM64LayoutResolver(catalog: catalog(result)).resolveLayout(ofType: "T"))
    }

    // Condition: packed bodyless pointers stay outside the new grammar; reversion retains refusal.
    func testPackedPointerRefused() { assertRefused("typedef struct __attribute__((packed)) T *A;") }

    // Condition: vector attributes cannot convert an opaque pointer alias into a vector; reversion retains refusal.
    func testVectorAttributedPointerRefused() { assertRefused("typedef struct __attribute__((vector_size(16))) T *A;") }

    // Condition: unknown attributes cannot be silently discarded on bodyless pointers; reversion retains refusal.
    func testUnknownAttributedPointerRefused() { assertRefused("typedef struct __attribute__((mystery)) T *A;") }


    // Condition: attributes after the tag are also excluded; reversion keeps the same missing-body refusal.
    func testPostTagAttributeRefused() { assertRefused("typedef struct T __attribute__((aligned(16))) *A;") }

    // Condition: an attribute after the alias cannot be swallowed by the terminator check; reversion retains refusal.
    func testPostAliasAttributeRefused() { assertRefused("typedef struct T *A __attribute__((aligned(16)));") }

    // Condition: a qualifier or keyword is not an alias name; reversion would emit a typedef named after it.
    func testQualifierAndKeywordAliasesRefused() {
        for word in ["volatile", "const", "restrict", "_Atomic", "_Nonnull"] {
            assertRefused("typedef struct T *\(word);", alias: word)
        }
    }

    // Condition: an alias equal to a later bodied record tag must not displace that record; reversion drops record A.
    func testPointerAliasCollidingWithLaterRecordTagKeepsRecord() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct A { int x; }; struct Holder { struct A value; };")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .struct)
        XCTAssertEqual(types["A"]?.fields, fields([("x", "int32_t")]))
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 4)
        XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 4)
    }

    // Condition: a different-tag completion still admits the pointer alias; reversion of the guard would not change this.
    func testPointerAliasWithDifferentLaterTagStillAdmitted() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct T { int x; }; struct Holder { A p; };")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .typedef)
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 8)
        XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 8)
    }

    // Condition: a by-value reference to a never-defined tag equal to the alias must stay unresolved; reversion makes Holder 8/8 via the pointer alias.
    func testByValueReferenceWithoutBodyStaysUnresolved() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct Holder { struct A v; };")
        let types = catalog(result)
        XCTAssertNotEqual(types["A"]?.kind, .typedef)
        XCTAssertNil(TypeDefinition.size(ofType: "Holder", in: types))
    }

    // Condition: an attributed later record named like the alias keeps its body; reversion drops record A.
    func testAttributedLaterRecordTagCollisionKeepsRecord() {
        let result = CTypeHeaderParser.parse("typedef struct T *A; struct __attribute__((packed)) A { int x; }; struct Holder { struct A value; };")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .struct)
        // A packed record has alignment 1, so Holder is 4/1; the pointer alias would make it 8/8.
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 4)
        XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 1)
    }

    // The following three preserved 855 regressions fail before the fix.

    // 855 Q1.1: compiler type/qualifier tokens are not typedef declarator names.
    func test855SupportedExtensionSpecifierCannotBecomePointerAlias() {
        for word in ["__int128", "__const__"] {
            assertRefused("typedef struct T *\(word);", alias: word)
        }
    }

    // 855 Q2.1: the flat catalog must not let a pointer alias displace an enum tag.
    func test855EnumTagCollisionRefusesPointerAliasInEitherOrder() {
        for source in [
            "typedef struct T *A; enum A { X };",
            "enum A { X }; typedef struct T *A;"
        ] {
            let result = CTypeHeaderParser.parse(source + " typedef int After;")
            let types = catalog(result)
            XCTAssertEqual(types["A"]?.kind, .enum)
            XCTAssertTrue(result.diagnostics.contains(missingBody))
            XCTAssertEqual(types["After"]?.fields.first?.type, "int32_t")
        }
    }

    // 855 Q2.2: refusing an alias must not silently reinterpret its uses as the tag.
    func test855RejectedPointerAliasCannotBecomeOrdinaryRecordMember() throws {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct A { int x; }; struct Holder { A p; };")
        let types = catalog(result)
        // Refusing the dependent aggregate is a safe outcome.
        guard let holder = types["Holder"] else { return }
        // Keeping a shortened aggregate by dropping p would not be safe.
        let member = try XCTUnwrap(holder.fields.first { $0.name == "p" })
        let silentlyRebound = types["A"]?.kind == .struct
            && member.type == "A" && member.layoutIsUnknown != true
        // Allows explicit pointer expansion, separated namespaces, or an unknown field.
        XCTAssertFalse(silentlyRebound,
            "Bare A denotes the pointer typedef, not the unrelated struct tag A.")
    }
    // SPEC 1-2: fails before the fix; pin exact recovery diagnostics.
    func test858ReservedSpellingsHaveExactlyMissingBody() {
        for word in ["__int128", "__const__"] {
            let result = CTypeHeaderParser.parse("typedef struct T *\(word); typedef int After;")
            XCTAssertEqual(result.types.map(\.name), ["After"])
            XCTAssertEqual(result.types.first?.fields, fields([("After", "int32_t")]))
            XCTAssertEqual(result.diagnostics, [missingBody])
        }
    }

    // SPEC 3: fails before the fix.
    func test858TwoReservedRefusalsRecoverToDistinctPointer() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *__int128; typedef union T *__const__; typedef struct U *B;")
        XCTAssertEqual(result.types.map(\.name), ["B"])
        XCTAssertEqual(result.types.first?.fields, fields([("B", "struct U *")]))
        XCTAssertEqual(result.diagnostics, [missingBody, missingBody])
    }

    // SPEC 4-5: fails before the fix; pin the enum and exact diagnostic in both orders.
    func test858EnumCollisionHasExactContentsAndDiagnostic() {
        for source in ["typedef struct T *A; enum A { X };",
                       "enum A { X }; typedef struct T *A;"] {
            let result = CTypeHeaderParser.parse(source + " typedef int After;")
            let types = catalog(result)
            XCTAssertEqual(types["A"]?.kind, .enum)
            XCTAssertEqual(types["A"]?.fields, fields([("X", "0")]))
            XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
            XCTAssertEqual(result.diagnostics, [missingBody])
        }
    }

    // SPEC 6: positive control (passes before).
    func test858LaterUnionTagRemainsAUnion() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; union A { int x; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .union)
        XCTAssertEqual(types["A"]?.fields, fields([("x", "int32_t")]))
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 7: positive control (passes before).
    func test858EarlierUnionTagRemainsAUnion() {
        let result = CTypeHeaderParser.parse(
            "union A { int x; }; typedef struct T *A; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .union)
        XCTAssertEqual(types["A"]?.fields, fields([("x", "int32_t")]))
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 8: fails before the fix; an explicit tag reference is not a bare alias use.
    func test858IncompleteEnumReferenceCannotResolveThroughPointerAlias() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct Holder { enum A e; }; typedef int After;")
        let types = catalog(result)
        XCTAssertNil(types["A"])
        XCTAssertEqual(types["Holder"]?.fields, fields([("e", "A")]))
        XCTAssertNil(TypeDefinition.size(ofType: "Holder", in: types))
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 9: fails before the fix; packed enum completeness is not asserted here.
    func test858AttributedEnumTagIsCollected() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; enum __attribute__((packed)) A { X }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .enum)
        XCTAssertEqual(types["A"]?.fields, fields([("X", "0")]))
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 10: fails before the fix; require the chosen expansion, not an absent Holder.
    func test858LaterStructCollisionExpandsBareMemberExactly() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct A { int x; }; struct Holder { A p; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .struct)
        XCTAssertEqual(types["A"]?.fields, fields([("x", "int32_t")]))
        XCTAssertEqual(types["Holder"]?.fields, fields([("p", "struct T *")]))
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 8)
        XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 8)
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 11: fails before the fix; same exact outcome with the record first.
    func test858EarlierStructCollisionExpandsBareMemberExactly() {
        let result = CTypeHeaderParser.parse(
            "struct A { int x; }; typedef struct T *A; struct Holder { A p; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .struct)
        XCTAssertEqual(types["Holder"]?.fields, fields([("p", "struct T *")]))
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 8)
        XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 8)
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 12: fails before the fix, including the same-size pointer-to-alias case.
    func test858BareAliasSiblingDeclaratorsExpandExactly() {
        let cases: [(String, [(String, String)], Int)] = [
            ("const A p;", [("p", "struct T *")], 8),
            ("A *q;", [("q", "struct T * *")], 8),
            ("A a1, a2;", [("a1", "struct T *"), ("a2", "struct T *")], 16),
            ("A arr[2];", [("arr", "struct T *[2]")], 16),
        ]
        for (members, expected, size) in cases {
            let result = CTypeHeaderParser.parse(
                "typedef struct T *A; struct A { int x; }; struct Holder { \(members) }; typedef int After;")
            let types = catalog(result)
            XCTAssertEqual(types["Holder"]?.fields, fields(expected), members)
            XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), size, members)
            XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 8, members)
            XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
            XCTAssertEqual(result.diagnostics, [missingBody], members)
        }
    }

    // SPEC 13: positive control (passes before); exact membership, not a prefix ban.
    func test858LongerIdentifierIsNotAReservedWord() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *__int128_t; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["__int128_t"]?.kind, .typedef)
        XCTAssertEqual(types["__int128_t"]?.fields, fields([("__int128_t", "struct T *")]))
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // SPEC 14: positive control (passes before); the refusal moves to an earlier guard.
    func test858ReservedTagFilterDoesNotChangeExistingRecordOutcome() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *__int128; struct __int128 { int x; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(result.types.map(\.name), ["__int128", "After"])
        XCTAssertEqual(types["__int128"]?.kind, .struct)
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 16: positive control (passes before); explicit tag namespaces bypass expansion.
    func test858ExplicitStructMemberStillUsesTheRecord() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct A { int x; }; struct Holder { struct A value; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.fields, fields([("x", "int32_t")]))
        XCTAssertEqual(types["Holder"]?.fields, fields([("value", "A")]))
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 4)
        XCTAssertEqual(TypeDefinition.alignment(ofType: "Holder", in: types), 4)
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // SPEC 17: positive control (passes before); do not change lenient unrelated names.
    func test858BareNameWithoutRefusedTypedefIsUnchanged() {
        let result = CTypeHeaderParser.parse(
            "struct A { int x; }; struct Holder { A p; }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["Holder"]?.fields, fields([("p", "A")]))
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 4)
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    // SPEC 20: positive control (passes before); enumerator names are not tags.
    func test858AnonymousEnumDoesNotReserveAliasName() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; enum { X }; typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(types["A"]?.kind, .typedef)
        XCTAssertEqual(types["A"]?.fields, fields([("A", "struct T *")]))
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, ["Skipped an anonymous enum (no tag/typedef name)."])
    }

    // SPEC 21: positive control (passes before); prototypes retain their independent context.
    func test858PrototypeExpansionAfterCatalogRefusalIsUnchanged() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct A { int x; }; void f(A p); typedef int After;")
        let types = catalog(result)
        XCTAssertEqual(result.prototypes.count, 1)
        XCTAssertEqual(result.prototypes.first?.name, "f")
        XCTAssertEqual(result.prototypes.first?.signature.returnType, "void")
        XCTAssertEqual(result.prototypes.first?.signature.args.map(\.type), ["struct T *"])
        XCTAssertEqual(types["A"]?.kind, .struct)
        XCTAssertEqual(types["After"]?.fields, fields([("After", "int32_t")]))
        XCTAssertEqual(result.diagnostics, [missingBody])
    }

    // Sibling consumer of SPEC 12: fails before the fix; no transitive bare rebinding.
    func test858PlainTypedefConsumerCarriesTheRefusedPointerTarget() {
        let result = CTypeHeaderParser.parse(
            "typedef struct T *A; struct A { int x; }; typedef A B; struct Holder { B p; };")
        let types = catalog(result)
        XCTAssertEqual(types["B"]?.fields, fields([("B", "struct T *")]))
        XCTAssertEqual(types["Holder"]?.fields, fields([("p", "B")]))
        XCTAssertEqual(TypeDefinition.size(ofType: "Holder", in: types), 8)
        XCTAssertEqual(result.diagnostics, [missingBody])
    }
}
