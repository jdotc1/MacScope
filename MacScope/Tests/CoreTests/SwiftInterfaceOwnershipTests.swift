import XCTest
@testable import MacScope

/// NEW source-only controls; no compiler, binary, parser, or filesystem fixture.
final class SwiftInterfaceOwnershipTests: XCTestCase {
    private func type(_ name: String = "Widget", _ address: UInt64? = nil,
                      _ qualified: String? = nil) -> SwiftTypeDescriptor {
        SwiftTypeDescriptor(kind: .struct, name: name, descriptorAddress: address, qualifiedName: qualified)
    }
    private func conformance(_ name: String = "Widget", _ proto: String = "P",
                             _ address: UInt64? = nil, _ qualified: String? = nil,
                             _ protocolQualified: String? = nil) -> SwiftConformance {
        SwiftConformance(typeName: name, protocolName: proto, typeDescriptorAddress: address,
                         typeQualifiedName: qualified, protocolQualifiedName: protocolQualified)
    }
    private func render(_ types: [SwiftTypeDescriptor], _ conformances: [SwiftConformance]) -> String {
        SwiftInterfaceRenderer.render(types: types, conformances: conformances)
    }

    func testDescriptorOwnsOnlyItsSameNamedNominal() {
        XCTAssertEqual(render([type("Widget", 1, "A.Widget"), type("Widget", 2, "B.Widget")],
                              [conformance("Widget", "P", 2, "B.Widget")]),
                       "struct Widget {\n}\n\nstruct Widget: P {\n}")
    }
    func testQualifiedOwnershipWithoutDescriptor() {
        XCTAssertEqual(render([type("Widget", 1, "A.Widget"), type("Widget", 2, "B.Widget")],
                              [conformance("Widget", "P", nil, "A.Widget")]),
                       "struct Widget: P {\n}\n\nstruct Widget {\n}")
    }
    func testLegacyUniqueOutputAndDeduplicationAreUnchanged() {
        XCTAssertEqual(render([type()], [conformance(), conformance(), conformance("Widget", "Q")]),
                       "struct Widget: P, Q {\n}")
        XCTAssertEqual(render([], [conformance("External")]), "extension External: P {}")
    }
    func testAmbiguousBareNameAttachesNeither() {
        let output = render([type("Widget", 1, "A.Widget"), type("Widget", 2, "B.Widget")], [conformance()])
        XCTAssertFalse(output.contains("struct Widget:"))
        XCTAssertTrue(output.contains("// Unresolved Swift conformance (ambiguous or conflicting identity)"))
    }
    func testUnresolvedExplicitDescriptorCannotFallBack() {
        let output = render([type("Widget", 1, "A.Widget")], [conformance("Widget", "P", 2, "A.Widget")])
        XCTAssertFalse(output.contains("struct Widget:"))
        XCTAssertFalse(output.contains("extension "))
        XCTAssertTrue(output.contains("unresolved local descriptor"))
        XCTAssertTrue(output.contains("descriptor=0x2"))
    }
    func testDuplicateDescriptorRowsRefuseEvenEqualRows() {
        let nominal = type("Widget", 1, "A.Widget")
        for input in [[nominal, nominal], [nominal, type("Other", 1, "B.Other")]] {
            let output = render(input, [conformance("Widget", "P", 1, "A.Widget")])
            XCTAssertFalse(output.contains("struct Widget:"))
            XCTAssertTrue(output.contains("Unresolved Swift conformance"))
        }
    }
    func testConflictingQualifierAndSimpleIdentityRefuseDescriptorFallback() {
        for c in [conformance("Widget", "P", 1, "B.Widget"), conformance("Other", "P", 1, "A.Widget")] {
            XCTAssertFalse(render([type("Widget", 1, "A.Widget")], [c]).contains("struct Widget:"))
        }
    }
    func testConflictingClaimsAreOrderIndependentWhenNominalQualifierMissing() {
        let claims = [conformance("Widget", "P", 1, "A.Widget"), conformance("Widget", "Q", 1, "B.Widget")]
        for input in [claims, Array(claims.reversed())] {
            let output = render([type("Widget", 1)], input)
            XCTAssertFalse(output.contains("struct Widget:"))
            XCTAssertEqual(output.components(separatedBy: "// Unresolved Swift conformance").count, 3)
        }
    }
    func testDescriptorCannotClaimAnotherNominalsQualifiedIdentity() {
        let unqualified = type("Widget", 1)
        let qualified = type("Widget", 2, "A.Widget")
        let claims = [conformance("Widget", "P", 1, "A.Widget"),
                      conformance("Widget", "Q", 2, "A.Widget")]
        let cases: [([SwiftTypeDescriptor], String)] = [
            ([unqualified, qualified], "struct Widget {\n}\n\nstruct Widget: Q {\n}"),
            ([qualified, unqualified], "struct Widget: Q {\n}\n\nstruct Widget {\n}")
        ]
        let diagnostic = "// Unresolved Swift conformance (ambiguous or conflicting identity): type=Widget; qualified=A.Widget; descriptor=0x1; protocol=P; protocolQualified=<absent>"
        for (nominals, declarations) in cases {
            for input in [claims, Array(claims.reversed())] {
                XCTAssertEqual(render(nominals, input), declarations + "\n\n" + diagnostic)
            }
        }
    }
    func testDescriptorCannotSelectAmongConflictingQualifiedOwners() {
        let nominals = [type("Widget", 1), type("Widget", 2, "A.Widget"),
                        type("Widget", 3, "A.Widget")]
        let claims = [conformance("Widget", "P", 1, "A.Widget"),
                      conformance("Widget", "Q", 2, "A.Widget")]
        for types in [nominals, Array(nominals.reversed())] {
            for input in [claims, Array(claims.reversed())] {
                let output = render(types, input)
                XCTAssertFalse(output.contains("struct Widget:"))
                XCTAssertFalse(output.contains("extension "))
                XCTAssertEqual(output.components(separatedBy: "// Unresolved Swift conformance").count, 3)
                XCTAssertTrue(output.contains("descriptor=0x1; protocol=P;"))
                XCTAssertTrue(output.contains("descriptor=0x2; protocol=Q;"))
            }
        }
    }
    func testDistinctQualifiedProtocolsAndIdenticalRepeatKeepStableOrder() {
        let p = conformance("Widget", "P", nil, nil, "B.P")
        XCTAssertEqual(render([type()], [p, conformance("Widget", "P", nil, nil, "A.P"), p]),
                       "struct Widget: B.P, A.P {\n}")
    }
    func testDistinctQualifiedOrphansDoNotCollapse() {
        XCTAssertEqual(render([], [conformance("Widget", "P", nil, "A.Widget"),
                                   conformance("Widget", "Q", nil, "B.Widget"),
                                   conformance("Widget", "R", nil, "A.Widget")]),
                       "extension A.Widget: P, R {}\n\nextension B.Widget: Q {}")
    }
    func testConflictingQualifiedOrphanClaimsRemainDiagnostics() {
        let output = render([], [conformance("Widget", "P", nil, "A.Widget"),
                                 conformance("Other", "Q", nil, "A.Widget")])
        XCTAssertFalse(output.contains("extension "))
        XCTAssertEqual(output.components(separatedBy: "// Unresolved Swift conformance").count, 3)
    }
    func testDuplicateQualifiedNominalsCannotChooseFirst() {
        let output = render([type("Widget", 1, "A.Widget"), type("Widget", 2, "A.Widget")],
                            [conformance("Widget", "P", nil, "A.Widget")])
        XCTAssertFalse(output.contains("struct Widget:"))
        XCTAssertTrue(output.contains("Unresolved Swift conformance"))
        // A descriptor-only record must not evade a contradictory retained qualified identity.
        let claims = [conformance("Widget", "P", 1), conformance("Other", "Q", nil, "A.Widget")]
        for input in [claims, Array(claims.reversed())] {
            let conflicted = render([type("Widget", 1, "A.Widget")], input)
            XCTAssertFalse(conflicted.contains("struct Widget:"))
            XCTAssertFalse(conflicted.contains("extension "))
        }
    }
    func testQualifiedLookupCannotEvadeDuplicateDescriptor() {
        let output = render([type("Widget", 1, "A.Widget"), type("Other", 1, "B.Other")],
                            [conformance("Widget", "P", nil, "A.Widget")])
        XCTAssertFalse(output.contains("struct Widget:"))
    }
    func testBareLegacyCannotOverrideConflictingRetainedQualifiers() {
        let output = render([type("Widget", 1, "A.Widget")],
                            [conformance(), conformance("Widget", "Q", nil, "B.Widget")])
        XCTAssertFalse(output.contains("struct Widget:"))
        XCTAssertTrue(output.contains("extension B.Widget: Q {}"))
    }
    func testDiagnosticControlsRemainOneCommentLineAndRawEvidenceVisible() {
        let output = render([], [conformance("Bad\nName", "<raw>\r\u{2028}\\", 7)])
        XCTAssertEqual(output.split(separator: "\n").count, 1)
        XCTAssertTrue(output.contains("Bad\\u{a}Name"))
        XCTAssertTrue(output.contains("<raw>\\u{d}\\u{2028}\\u{5c}"))
        XCTAssertFalse(output.contains("extension "))
    }
    func testUnnameableQualifiedOrphanRemainsDiagnostic() {
        let output = render([], [conformance("Widget", "P", nil, "<ext:mangled>.Widget")])
        XCTAssertTrue(output.contains("unnameable orphan evidence"))
        XCTAssertFalse(output.contains("extension "))
    }
    func testContradictoryProtocolQualifiedIdentityDoesNotChooseFirst() {
        let output = render([type()], [conformance("Widget", "P", nil, nil, "A.P"),
                                      conformance("Widget", "Other", nil, nil, "A.P")])
        XCTAssertFalse(output.contains("struct Widget:"))
        XCTAssertTrue(output.contains("conflicting protocol identity"))
    }
    func testEmptyUnknownKindAndMembersRemainUnchanged() {
        XCTAssertEqual(render([], []), "")
        let nominal = SwiftTypeDescriptor(kind: .unknown, name: "Opaque", fields: [
            SwiftField(name: "known", typeName: "Int", isVar: true), SwiftField(name: "unresolved")], rawKind: 31)
        XCTAssertEqual(render([nominal], []),
                       "/* Swift type with kind 31 */ Opaque {\n    var known: Int\n    let unresolved\n}")
        XCTAssertEqual(render([SwiftTypeDescriptor(kind: .enum, name: "E", fields: [SwiftField(name: "x", typeName: "Int")])], []),
                       "enum E {\n    case x(Int)\n}")
    }
}
