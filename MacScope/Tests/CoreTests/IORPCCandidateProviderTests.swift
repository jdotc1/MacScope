import Foundation
import XCTest
@testable import MacScopeAnalysisCore

/// Only fresh in-memory synthetic archives are admitted by these tests;
/// the provider never performs archive admission itself.
final class IORPCCandidateProviderTests: XCTestCase {
    private let target = "arm64-apple-driverkit25.0"
    private let admission = "requires Lane A exact-build/source admission; no message dispatch or class association inferred"
    private func row(_ name: String = "Start", value: String = "18446744073709551615", enumID: String = "e", status: String = "unadmitted-candidate") -> String {
        """
        {"enumTypeID":"\(enumID)","name":"\(name)","id":\(value),"origin":{"header":"Messages.h","line":1,"column":1},"status":"\(status)"}
        """
    }
    private func section(_ rows: [String]) -> String {
        """
        {"sdkRelease":"25.0","sdkBuild":"synthetic","architecture":"arm64","constants":[\(rows.joined(separator: ","))],"admission":"\(admission)"}
        """
    }
    private func enumNode(_ id: String = "e", values: String = "{\"name\":\"Start\",\"value\":\"18446744073709551615\"}") -> String {
        """
        {"id":"\(id)","kind":"enumeration","spelling":"Messages","layout":{"status":"known","sizeBytes":8,"alignmentBytes":8},"underlyingTypeID":"u","fields":[],"enumValues":[\(values)],"qualifiers":[],"origin":{"header":"Messages.h","line":1,"column":1}}
        """
    }
    private func archive(_ section: String?, enums: [String]? = nil, edit: (String) -> String = { $0 }) throws -> SDKTypeArchive {
        let optional = section.map { ",\"iorpcConstantCandidates\":" + $0 } ?? ""
        let source = """
        {"schema":"macscope.sdk-type-archive","schemaMajor":1,"schemaMinor":0,"configurationID":"\(String(repeating: "a", count: 64))","provenance":{"compiler":"synthetic","compilerVersion":"1","libclangVersion":"1","sdkIdentity":"synthetic|25.0|synthetic","targetTriple":"\(target)","language":"c","extractorVersion":"synthetic","input":"Messages.h","inputSHA256":"\(String(repeating: "b", count: 64))","arguments":[],"sdkRelease":"25.0","sdkBuild":"synthetic","architecture":"arm64"\(optional)},"diagnostics":[],"types":[{"id":"u","kind":"scalar","spelling":"uint64_t","layout":{"status":"known","sizeBytes":8,"alignmentBytes":8},"signed":false,"fields":[],"enumValues":[],"qualifiers":[]},\((enums ?? [enumNode()]).joined(separator: ","))]}
        """
        return try SDKTypeArchive.decode(Data(edit(source).utf8), expectedTarget: target)
    }
    func testExactUInt64AndExistingIdentityAreRetained() throws {
        let source = try archive(section([row()]))
        let identity = source.contentSHA256
        let first = try IORPCCandidateProvider(archive: source)
        let second = try IORPCCandidateProvider(archive: source)
        XCTAssertEqual(first.projection.candidates.first?.id, UInt64.max)
        XCTAssertEqual(first.projection.candidates.first?.identity, source.identity(for: "e"))
        XCTAssertEqual(first.projection.candidates.first?.origin.header, "Messages.h")
        XCTAssertEqual(first.projection.candidates.first?.status, .unadmittedCandidate)
        XCTAssertEqual(first.projection.configurationID, source.document.configurationID)
        XCTAssertEqual(first.projection.archiveSHA256, identity)
        XCTAssertEqual(source.contentSHA256, identity)
        XCTAssertEqual(first.encodedProjection(), second.encodedProjection())
    }
    func testAbsentAndPresentEmptyDiffer() throws {
        XCTAssertEqual(try IORPCCandidateProvider(archive: archive(nil)).projection.presence, .absent)
        let empty = try IORPCCandidateProvider(archive: archive(section([])))
        XCTAssertEqual(empty.projection.presence, .present)
        XCTAssertTrue(empty.projection.candidates.isEmpty)
        // Null is malformed, not absence and not a present empty list.
        let null = try archive("null")
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: null))
    }
    func testWithinEnumAliasesRemainAmbiguous() throws {
        let values = "{\"name\":\"Start\",\"value\":\"7\"},{\"name\":\"Alias\",\"value\":\"7\"}"
        let source = try archive(section([row(value: "7", status: "ambiguous-numeric-alias"), row("Alias", value: "7", status: "ambiguous-numeric-alias")]), enums: [enumNode(values: values)])
        XCTAssertTrue(try IORPCCandidateProvider(archive: source).projection.candidates.allSatisfy { $0.status == .ambiguousNumericAlias })
    }
    func testAcrossEnumsAliasesRemainAmbiguous() throws {
        let source = try archive(section([row(status: "ambiguous-numeric-alias"), row(enumID: "other", status: "ambiguous-numeric-alias")]), enums: [enumNode(), enumNode("other")])
        XCTAssertEqual(try IORPCCandidateProvider(archive: source).projection.candidates.map(\.status), [.ambiguousNumericAlias, .ambiguousNumericAlias])
    }
    func testMissingEnumAndWrongKindRefuse() throws {
        for id in ["missing", "u"] {
            let source = try archive(section([row(enumID: id)]))
            XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
        }
    }
    func testWrongNameValueAndOriginRefuseAtomically() throws {
        for bad in [row("Other"), row(value: "7"), row().replacingOccurrences(of: "Messages.h", with: "Forged.h")] {
            let source = try archive(section([bad]))
            XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
        }
    }
    func testDuplicateRecordsRefuse() throws {
        let source = try archive(section([row(), row()]))
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
    }
    func testDuplicateDecodedJSONKeysRefuse() throws {
        let duplicate = row().replacingOccurrences(of: "\"id\":", with: "\"\\u0069d\":0,\"id\":")
        let source = try archive(section([duplicate]))
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
        // Duplicate keys outside the optional section must not bypass the scanner.
        let outside = try archive(nil, edit: {
            $0.replacingOccurrences(of: "\"diagnostics\":[]", with: "\"diagnostics\":[],\"\\u0064iagnostics\":[]")
        })
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: outside))
    }
    func testUnknownKeysAndForgedStatusRefuse() throws {
        for bad in [row(status: "admitted"), row().replacingOccurrences(of: "\"name\":", with: "\"authority\":true,\"name\":")] {
            let source = try archive(section([bad]))
            XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
        }
    }
    func testUInt64OverflowAndNonintegerFormsRefuse() throws {
        for value in ["18446744073709551616", "1.0", "1e2", "-1", "true", "\"7\""] {
            let source = try archive(section([row(value: value)]))
            XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
        }
    }
    func testContradictorySelectionAndSDKLabelsRefuse() throws {
        let a = try archive(section([row()]).replacingOccurrences(of: "25.0", with: "26.0"))
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: a))
        let b = try archive(section([row()]), edit: { $0.replacingOccurrences(of: "synthetic|25.0|synthetic", with: "synthetic|26.0|synthetic") })
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: b))
    }
    func testOmittedAliasCannotBecomeUnique() throws {
        let values = "{\"name\":\"Start\",\"value\":\"7\"},{\"name\":\"Alias\",\"value\":\"7\"}"
        let source = try archive(section([row(value: "7")]), enums: [enumNode(values: values)])
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: source))
    }
    func testTextAndCountBudgetsRefuse() throws {
        let long = try archive(section([row(String(repeating: "x", count: 16_385))]))
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: long))
        let many = try archive(section(Array(repeating: row(), count: 10_001)))
        XCTAssertThrowsError(try IORPCCandidateProvider(archive: many))
    }
    func testUnknownLayoutsAreNotChanged() throws {
        let source = try archive(section([row()]), edit: { $0.replacingOccurrences(of: "\"status\":\"known\",\"sizeBytes\":8,\"alignmentBytes\":8", with: "\"status\":\"unknown\",\"reason\":\"synthetic incomplete\"") })
        let before = source.document
        _ = try IORPCCandidateProvider(archive: source)
        XCTAssertEqual(source.document, before)
        XCTAssertTrue(source.document.types.allSatisfy { $0.layout.status == .unknown })
    }
}
