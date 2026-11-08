import Foundation
import XCTest
@testable import MacScopeAnalysisCore

/// Proposed fresh synthetic definitions only.
final class IORPCObservationLookupTests: XCTestCase {
    private let target = "arm64-apple-driverkit25.0"
    private let authority = "requires Lane A exact-build/source admission; no message dispatch or class association inferred"
    private struct Entry {
        let declaration: String
        let name: String
        let value: UInt64
        let header: String
        let line: UInt32
        let column: UInt32
        init(_ name: String, _ value: UInt64,
             header: String = "Lookup.h", line: UInt32 = 3, column: UInt32 = 2) {
            self.init("e", name, value, header: header, line: line, column: column)
        }
        init(_ declaration: String, _ name: String, _ value: UInt64,
             header: String = "Lookup.h", line: UInt32 = 3, column: UInt32 = 2) {
            self.declaration = declaration; self.name = name; self.value = value
            self.header = header; self.line = line; self.column = column
        }
    }
    private func quoted(_ value: String) throws -> String {
        String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
    }
    private func fixture(_ entries: [Entry], absent: Bool = false, unknown: Bool = false) throws -> SDKTypeArchive {
        let layout = unknown ? "{\"status\":\"unknown\",\"reason\":\"synthetic incomplete\"}" : "{\"status\":\"known\",\"sizeBytes\":8,\"alignmentBytes\":8}"
        func origin(_ e: Entry) throws -> String {
            "{\"header\":\(try quoted(e.header)),\"line\":\(e.line),\"column\":\(e.column)}"
        }
        var nodes: [String] = []
        for id in Set(entries.map(\.declaration)).sorted() {
            let group = entries.filter { $0.declaration == id }
            let first = try XCTUnwrap(group.first)
            let values = try group.map { "{\"name\":\(try quoted($0.name)),\"value\":\(try quoted(String($0.value)))}" }.joined(separator: ",")
            nodes.append("{\"id\":\(try quoted(id)),\"kind\":\"enumeration\",\"spelling\":\"SyntheticMessages\",\"layout\":\(layout),\"underlyingTypeID\":\"u\",\"fields\":[],\"enumValues\":[\(values)],\"qualifiers\":[],\"origin\":\(try origin(first))}")
        }
        var counts: [UInt64: Int] = [:]
        for entry in entries { counts[entry.value, default: 0] += 1 }
        let rows = try entries.map { e -> String in
            let status = counts[e.value, default: 0] > 1 ? "ambiguous-numeric-alias" : "unadmitted-candidate"
            return "{\"enumTypeID\":\(try quoted(e.declaration)),\"name\":\(try quoted(e.name)),\"id\":\(e.value),\"origin\":\(try origin(e)),\"status\":\(try quoted(status))}"
        }.joined(separator: ",")
        let section = absent ? "" : ",\"iorpcConstantCandidates\":{\"sdkRelease\":\"25.0\",\"sdkBuild\":\"lookup-synthetic\",\"architecture\":\"arm64\",\"constants\":[\(rows)],\"admission\":\(try quoted(authority))}"
        let suffix = nodes.isEmpty ? "" : "," + nodes.joined(separator: ",")
        let source = """
        {"schema":"macscope.sdk-type-archive","schemaMajor":1,"schemaMinor":0,"configurationID":"\(String(repeating: "c", count: 64))","provenance":{"compiler":"lookup synthetic","compilerVersion":"1","libclangVersion":"1","sdkIdentity":"synthetic|25.0|lookup-synthetic","targetTriple":"\(target)","language":"c","extractorVersion":"lookup synthetic","input":"Lookup.h","inputSHA256":"\(String(repeating: "d", count: 64))","arguments":[],"sdkRelease":"25.0","sdkBuild":"lookup-synthetic","architecture":"arm64"\(section)},"diagnostics":[],"types":[{"id":"u","kind":"scalar","spelling":"uint64_t","layout":\(layout),"signed":false,"fields":[],"enumValues":[],"qualifiers":[]}\(suffix)]}
        """
        return try SDKTypeArchive.decode(Data(source.utf8), expectedTarget: target)
    }
    private func provider(_ entries: [Entry]) throws -> IORPCCandidateProvider {
        try IORPCCandidateProvider(archive: fixture(entries))
    }
    private func refusal(_ expected: IORPCCandidateProvider.LookupRefusal,
                         _ action: () throws -> IORPCCandidateProvider.LookupResult,
                         file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) {
            XCTAssertEqual($0 as? IORPCCandidateProvider.LookupRefusal, expected, file: file, line: line)
        }
    }

    func testExactUnsignedExtremesAndAboveDoublePrecision() throws {
        let ids: [UInt64] = [0, 1, 9_007_199_254_740_992, 9_007_199_254_740_993, 9_007_199_254_740_994, UInt64.max - 1, UInt64.max]
        let p = try provider(ids.enumerated().map { Entry("N\($0.offset)", $0.element) })
        for id in ids {
            let r = try p.lookup(id: id)
            XCTAssertEqual(r.projection.requestedID, id)
            XCTAssertEqual(r.projection.context.candidates.map(\.id), [id])
            let decoded = try JSONDecoder().decode(IORPCCandidateProvider.LookupProjection.self, from: r.encoded)
            XCTAssertEqual(decoded.requestedID, id)
            XCTAssertEqual(decoded.context.candidates.map(\.id), [id])
        }
        XCTAssertEqual(try p.lookup(id: 2).projection.outcome, .noObservedMatch)
    }
    func testWithinEnumReturnsEveryAmbiguousAlias() throws {
        let p = try provider([Entry("Zulu", 7), Entry("Alpha", 7), Entry("Other", 8)])
        let rows = try p.lookup(id: 7).projection.context.candidates
        XCTAssertEqual(rows.map(\.name), ["Alpha", "Zulu"])
        XCTAssertTrue(rows.allSatisfy { $0.status == .ambiguousNumericAlias })
        XCTAssertEqual(rows.map(\.identity), [p.projection.candidates[0].identity, p.projection.candidates[0].identity])
    }
    func testAcrossEnumAliasesKeepDistinctDeclarationsAndOrigins() throws {
        let a = Entry("a", "Same", 19, header: "A.h", line: 7, column: 9)
        let b = Entry("b", "Same", 19, header: "B.h", line: 8, column: 10)
        let archive = try fixture([b, a])
        let rows = try IORPCCandidateProvider(archive: archive).lookup(id: 19).projection.context.candidates
        XCTAssertEqual(rows.map(\.identity), [try XCTUnwrap(archive.identity(for: "a")), try XCTUnwrap(archive.identity(for: "b"))])
        XCTAssertEqual(rows.map(\.origin.header), ["A.h", "B.h"])
        XCTAssertEqual(rows.map(\.origin.line), [7, 8])
        XCTAssertEqual(rows.map(\.origin.column), [9, 10])
        XCTAssertTrue(rows.allSatisfy { $0.status == .ambiguousNumericAlias })
    }
    func testSingleObservationRetainsContextWithoutAdmission() throws {
        let archive = try fixture([Entry("Only", 23)])
        let p = try IORPCCandidateProvider(archive: archive)
        let r = try p.lookup(id: 23).projection
        XCTAssertEqual(r.outcome, .observedMatches)
        XCTAssertEqual(r.context.candidates.first?.status, .unadmittedCandidate)
        XCTAssertEqual(r.context.archiveSHA256, archive.contentSHA256)
        XCTAssertEqual(r.context.configurationID, archive.document.configurationID)
        XCTAssertEqual(r.context.targetTriple, target)
        XCTAssertEqual(r.context.sdkIdentity, "synthetic|25.0|lookup-synthetic")
        XCTAssertEqual(r.context.sdkRelease, "25.0")
        XCTAssertEqual(r.context.sdkBuild, "lookup-synthetic")
        XCTAssertEqual(r.context.architecture, "arm64")
        XCTAssertEqual(r.context.authority, authority)
        XCTAssertEqual(r.context.presence, .present)
    }
    func testThreeNonmatchStatesRemainDistinct() throws {
        let absent = try IORPCCandidateProvider(archive: fixture([], absent: true)).lookup(id: 4).projection
        let empty = try provider([]).lookup(id: 4).projection
        let missing = try provider([Entry("One", 1)]).lookup(id: 4).projection
        XCTAssertEqual(absent.outcome, .sectionAbsent)
        XCTAssertEqual(absent.context.presence, .absent)
        XCTAssertNil(absent.context.sdkRelease)
        XCTAssertEqual(empty.outcome, .sectionEmpty)
        XCTAssertEqual(empty.context.presence, .present)
        XCTAssertEqual(missing.outcome, .noObservedMatch)
        XCTAssertTrue([absent, empty, missing].allSatisfy { $0.context.candidates.isEmpty })
    }
    func testPermutationHasLiteralUTF8SemanticOrderPerArchive() throws {
        let entries = [Entry("z", "a", 5), Entry("A", "é", 5), Entry("A", "a", 5), Entry("A", "Z", 5), Entry("é", "B", 5)]
        let first = try fixture(entries)
        let second = try fixture(Array(entries.reversed()))
        let left = try IORPCCandidateProvider(archive: first).lookup(id: 5).projection.context.candidates
        let right = try IORPCCandidateProvider(archive: second).lookup(id: 5).projection.context.candidates
        XCTAssertEqual(left.map { $0.identity.declarationID }, ["A", "A", "A", "z", "é"])
        XCTAssertEqual(left.map(\.name), ["Z", "a", "é", "a", "B"])
        XCTAssertEqual(left.map(\.name), right.map(\.name))
        XCTAssertEqual(left.map { $0.identity.declarationID }, right.map { $0.identity.declarationID })
        for row in left { XCTAssertEqual(row.identity, first.identity(for: row.identity.declarationID)) }
        for row in right { XCTAssertEqual(row.identity, second.identity(for: row.identity.declarationID)) }
        // No equality of whole result bytes or cross-archive digests is asserted.
    }
    func testRepeatedLookupIsStableAndProjectionUnchanged() throws {
        let p = try provider([Entry("B", 7), Entry("A", 7), Entry("C", 8)])
        let before = p.encodedProjection()
        let names = p.projection.candidates.map(\.name)
        let first = try p.lookup(id: 7)
        XCTAssertEqual(first.encoded, try p.lookup(id: 7).encoded)
        XCTAssertEqual(p.encodedProjection(), before)
        XCTAssertEqual(p.projection.candidates.map(\.name), names)
    }
    func testCountBoundaryAndZeroSlotsAreAtomic() throws {
        let p = try provider([Entry("A", 7), Entry("B", 7), Entry("C", 7)])
        XCTAssertEqual(try p.lookup(id: 7, budget: .init(maximumMatches: 3)).projection.context.candidates.count, 3)
        refusal(.matchCountExceeded) { try p.lookup(id: 7, budget: .init(maximumMatches: 2)) }
        refusal(.matchCountExceeded) { try p.lookup(id: 7, budget: .init(maximumMatches: 0)) }
        XCTAssertEqual(try p.lookup(id: 8, budget: .init(maximumMatches: 0)).projection.outcome, .noObservedMatch)
        XCTAssertEqual(try p.lookup(id: 7).projection.context.candidates.count, 3)
    }
    func testInvalidBudgetExtremesRefuse() throws {
        let p = try provider([])
        for count in [Int.min, -1, 10_001, Int.max] {
            refusal(.invalidBudget) { try p.lookup(id: 0, budget: .init(maximumMatches: count)) }
        }
        for bytes in [Int.min, -1, 0, IORPCCandidateProvider.maximumProjectionBytes + 1, Int.max] {
            refusal(.invalidBudget) { try p.lookup(id: 0, budget: .init(maximumEncodedBytes: bytes)) }
        }
    }
    func testMetadataByteRefusalAndEscapedTextPreservation() throws {
        let absent = try IORPCCandidateProvider(archive: fixture([], absent: true))
        let empty = try provider([])
        for p in [absent, empty] {
            refusal(.byteBudgetExceeded) { try p.lookup(id: 0, budget: .init(maximumEncodedBytes: 1)) }
        }
        let name = "Quote\" slash\\ newline\n tab\t é"
        let header = "Folder/quote\"back\\line\n.h"
        let p = try provider([Entry(name, 9, header: header)])
        refusal(.byteBudgetExceeded) { try p.lookup(id: 9, budget: .init(maximumEncodedBytes: 2048)) }
        let cap = 32_768
        let r = try p.lookup(id: 9, budget: .init(maximumEncodedBytes: cap))
        XCTAssertLessThanOrEqual(r.encoded.count, cap)
        let decoded = try JSONDecoder().decode(IORPCCandidateProvider.LookupProjection.self, from: r.encoded)
        XCTAssertEqual(decoded.context.candidates.first?.name, name)
        XCTAssertEqual(decoded.context.candidates.first?.origin.header, header)
        XCTAssertEqual(decoded.context.authority, authority)
    }
    func testLookupPreservesRetainedArchiveAndUnknownFacts() throws {
        let archive = try fixture([Entry("Unknown", 31)], unknown: true)
        let bytes = archive.encoded()
        let document = archive.document
        let identity = archive.contentSHA256
        let p = try IORPCCandidateProvider(archive: archive)
        let projection = p.encodedProjection()
        _ = try p.lookup(id: 31)
        _ = try p.lookup(id: 32)
        XCTAssertEqual(archive.encoded(), bytes)
        XCTAssertEqual(archive.document, document)
        XCTAssertEqual(archive.contentSHA256, identity)
        XCTAssertTrue(archive.document.types.allSatisfy { $0.layout.status == .unknown })
        XCTAssertEqual(p.encodedProjection(), projection)
    }
}
