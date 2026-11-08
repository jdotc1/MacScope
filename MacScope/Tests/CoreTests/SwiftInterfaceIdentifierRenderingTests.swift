import XCTest
@testable import MacScope

/// In-memory display fixtures; expected text does not establish compiler or parser acceptance.
final class SwiftInterfaceIdentifierRenderingTests: XCTestCase {
    private func render(_ name: String = "Record", _ fields: [SwiftField],
                        kind: SwiftTypeKind = .struct) -> String {
        SwiftInterfaceRenderer.render(types: [SwiftTypeDescriptor(kind: kind, name: name, fields: fields)])
    }
    func testOrdinaryOutputRemainsExact() {
        XCTAssertEqual(render("Record", [SwiftField(name: "value", typeName: "Int", isVar: true)]),
                       "struct Record {\n    var value: Int\n}")
    }
    func testRealKeywordFieldWitnesses() {
        XCTAssertEqual(render("Record", [SwiftField(name: "class", typeName: "String", isVar: true),
                                          SwiftField(name: "protocol", typeName: "Int")]),
                       "struct Record {\n    var `class`: String\n    let `protocol`: Int\n}")
    }
    func testKeywordOwnerAndRecordedIndirectCaseCompose() {
        XCTAssertEqual(render("class", [SwiftField(name: "case", typeName: "Int", isIndirectCase: true),
                                         SwiftField(name: "return")], kind: .enum),
                       "enum `class` {\n    indirect case `case`(Int)\n    case `return`\n}")
    }
    func testUnicodeSubsetAndCombiningContinuationPreserveScalars() {
        XCTAssertEqual(render("Café", [SwiftField(name: "δ", typeName: "Int"),
                                        SwiftField(name: "名前"), SwiftField(name: "e\u{301}")]),
                       "struct Café {\n    let δ: Int\n    let 名前\n    let e\u{301}\n}")
    }
    func testQualifiedComponentsAndRawIdentityDeduplication() {
        let a = SwiftConformance(typeName: "class", protocolName: "protocol",
                                 typeQualifiedName: "A.class", protocolQualifiedName: "P.protocol")
        let b = SwiftConformance(typeName: "class", protocolName: "protocol",
                                 typeQualifiedName: "B.class", protocolQualifiedName: "Q.protocol")
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [], conformances: [a, b, a]),
                       "extension A.`class`: P.`protocol` {}\n\nextension B.`class`: Q.`protocol` {}")
    }
    func testDescriptorAndQualifiedConflictsStillRefuse() {
        let nominal = SwiftTypeDescriptor(kind: .struct, name: "class", descriptorAddress: 1,
                                          qualifiedName: "A.class")
        let conflict = SwiftConformance(typeName: "class", protocolName: "protocol",
                                        typeDescriptorAddress: 1, typeQualifiedName: "B.class")
        let text = SwiftInterfaceRenderer.render(types: [nominal], conformances: [conflict])
        XCTAssertTrue(text.hasPrefix("struct `class` {\n}"))
        XCTAssertTrue(text.contains("Unresolved Swift conformance (ambiguous or conflicting identity)"))
        XCTAssertFalse(text.contains("struct `class`:"))
        let duplicate = SwiftInterfaceRenderer.render(types: [nominal, nominal], conformances: [
            SwiftConformance(typeName: "class", protocolName: "P", typeDescriptorAddress: 1)])
        XCTAssertFalse(duplicate.contains("struct `class`:"))
    }
    func testUnsupportedOwnerDoesNotReassignMembers() {
        XCTAssertEqual(render("A.B", [SwiftField(name: "value", typeName: "Int")]),
                       "// Unrenderable Swift type: name=A.B; kind=struct; rawKind=?\n// Retained member: name=value; type=Int; indirect=false")
    }
    func testRawSimpleDotsCannotMintQualifiedIdentity() {
        let text = SwiftInterfaceRenderer.render(types: [], conformances: [
            SwiftConformance(typeName: "A.B", protocolName: "P"),
            SwiftConformance(typeName: "Good", protocolName: "P.Q")])
        XCTAssertFalse(text.contains("extension "))
        XCTAssertTrue(text.contains("unnameable orphan evidence"))
        XCTAssertTrue(text.contains("unnameable protocol evidence"))
    }
    func testPreviouslyUnadmittedMangledPathRemainsEvidence() {
        let text = SwiftInterfaceRenderer.render(types: [], conformances: [
            SwiftConformance(typeName: "Widget", protocolName: "P", typeQualifiedName: "<ext:mangled>.Widget")])
        XCTAssertTrue(text.contains("unnameable orphan evidence"))
        XCTAssertFalse(text.contains("extension "))
    }
    func testUnsafeMemberIsOneReversibleCommentLine() {
        let raw = "bad\r\n`\"\\/*x*/\u{0}\u{85}\u{2028}\u{2029}"
        let text = render("Record", [SwiftField(name: raw, typeName: "Int")])
        XCTAssertEqual(text, "struct Record {\n    // Unrenderable Swift member: name=bad\\u{d}\\u{a}\\u{60}\\u{22}\\u{5c}\\u{2f}*x*\\u{2f}\\u{0}\\u{85}\\u{2028}\\u{2029}; type=Int; indirect=false\n}")
        XCTAssertEqual(text.split(separator: "\n").count, 3)
    }
    func testUnsupportedSingleNamesNeverBecomeDeclarations() {
        for name in ["", "_", "x y", "x-y", "1x", "{}; struct Evil {}", "`class`", "\u{301}x"] {
            XCTAssertTrue(render("Record", [SwiftField(name: name)]).contains("// Unrenderable Swift member:"))
        }
    }
    func testSupportedTypeDisplaysRemainExactNotWholeBackticks() {
        for type in ["Int?", "(Int, String?)", "Dictionary<String, Array<Int>>", "[String: [Int]]", "Swift.Int", "()"] {
            XCTAssertEqual(render("Record", [SwiftField(name: "value", typeName: type)]),
                           "struct Record {\n    let value: \(type)\n}")
        }
    }
    func testMissingAndUnsupportedTypeKeepUnknownWithoutManglingFallback() {
        XCTAssertEqual(render("Record", [SwiftField(name: "missing", mangledTypeName: "Si"),
                                          SwiftField(name: "bad", typeName: "Int\n} struct Evil {}")]),
                       "struct Record {\n    let missing\n    let bad // Unrenderable type: Int\\u{a}} struct Evil {}\n}")
        XCTAssertEqual(render("E", [SwiftField(name: "case", typeName: "<bad>", isIndirectCase: true)], kind: .enum),
                       "enum E {\n    indirect case `case` // Unrenderable type: <bad>\n}")
    }
    func testUnknownKindLabelAndNonEnumBindingsRemain() {
        let nominal = SwiftTypeDescriptor(kind: .unknown, name: "protocol", fields: [
            SwiftField(name: "class", isVar: true, isIndirectCase: true)], rawKind: 31)
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [nominal]),
                       "/* Swift type with kind 31 */ `protocol` {\n    var `class`\n}")
    }
    func testCombinedOwnershipIndirectAndKeywordRendering() {
        let a = SwiftTypeDescriptor(kind: .enum, name: "class", fields: [
            SwiftField(name: "case", typeName: "Int?", isIndirectCase: true)], descriptorAddress: 1, qualifiedName: "A.class")
        let b = SwiftTypeDescriptor(kind: .struct, name: "class", descriptorAddress: 2, qualifiedName: "B.class")
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [a, b], conformances: [
            SwiftConformance(typeName: "class", protocolName: "protocol", typeDescriptorAddress: 1,
                             typeQualifiedName: "A.class", protocolQualifiedName: "M.protocol")]),
                       "enum `class`: M.`protocol` {\n    indirect case `case`(Int?)\n}\n\nstruct `class` {\n}")
    }
    func testMalformedTypeDisplayCannotDecorateFailedChildren() {
        for type in ["Array<>", "[Int", "(Int,)", "Int class Evil", "Int/*x*/", "`class`", "$sSi", "Int\u{2028}String"] {
            let text = render("Record", [SwiftField(name: "value", typeName: type)])
            XCTAssertTrue(text.contains("let value // Unrenderable type:"))
            XCTAssertFalse(text.contains("let value:"))
            XCTAssertEqual(text.split(separator: "\n").count, 3)
        }
    }
    func testDiagnosticEscapeLookingTextRemainsDistinct() {
        let rawControl = render("Record", [SwiftField(name: "x\n")])
        let literalEscape = render("Record", [SwiftField(name: "x\\u{a}")])
        XCTAssertNotEqual(rawControl, literalEscape)
        XCTAssertTrue(rawControl.contains("x\\u{a}"))
        XCTAssertTrue(literalEscape.contains("x\\u{5c}u{a}"))
    }

}
