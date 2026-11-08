// Adapter tests: component declaration snapshots onto the donor entitlement comparison, and explicit architecture handling.

import Foundation
import XCTest
@testable import MacScope

final class CEEntitlementAdapterTests: XCTestCase {
    private let inventoryID = UUID(uuidString: "00000000-0000-0000-0000-0000000000a1")!
    private let componentID = UUID(uuidString: "00000000-0000-0000-0000-0000000000a2")!
    private let arm = CEHarness.key("arm64")
    private let x86 = CEHarness.key("x86_64")

    // MARK: Helpers

    private func dictionary(_ pairs: [(String, EntitlementValue)]) throws -> EntitlementDictionary {
        try EntitlementDictionary(entries: pairs.map { EntitlementEntry(key: $0.0, value: $0.1) })
    }

    private func present(_ values: EntitlementDictionary, category: CE.DeclarationCategory = .privacy,
                         architecture: CE.ExactUTF8Key? = nil) throws -> CE.ComponentEntitlementSnapshot {
        let path = category == .loadCommands ? "Contents/MacOS/OwnedMain" : "Contents/Resources/PrivacyInfo.xcprivacy"
        let source = CE.DeclarationSource(path: CEHarness.path(path), architecture: architecture)
        return try CE.ComponentEntitlementSnapshot(CE.DeclarationObservation(
            inventoryID: inventoryID, componentID: componentID, category: category, architecture: architecture,
            state: .present, values: values, source: source))
    }

    private func absent(architecture: CE.ExactUTF8Key? = nil) throws -> CE.ComponentEntitlementSnapshot {
        try CE.ComponentEntitlementSnapshot(CE.DeclarationObservation(
            inventoryID: inventoryID, componentID: componentID, category: .privacy, architecture: architecture,
            state: .notPresent, source: CE.DeclarationSource(path: CEHarness.path("Contents/Resources/PrivacyInfo.xcprivacy"),
                                                              architecture: architecture)))
    }

    private func unavailable(category: CE.DeclarationCategory = .privacy,
                             architecture: CE.ExactUTF8Key? = nil) throws -> CE.ComponentEntitlementSnapshot {
        let range = CE.PathRange.leaf(CEHarness.path("Contents/Resources/PrivacyInfo.xcprivacy"))
        let issue = CE.EvidenceIssue(.io(.read, errno: EIO, range), range: range)
        return try CE.ComponentEntitlementSnapshot(CE.DeclarationObservation(
            inventoryID: inventoryID, componentID: componentID, category: category, architecture: architecture,
            state: .unavailable, issue: issue))
    }

    private func expect<T>(_ expected: CE.EvidenceError, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> T) {
        do {
            _ = try body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? CE.EvidenceError, expected, file: file, line: line)
        }
    }

    /// Independent byte-key reference merge. Keys are compared as UTF-8 bytes, values with the donor's typed equality.
    private func reference(_ old: EntitlementDictionary, _ new: EntitlementDictionary)
        -> [(key: [UInt8], kind: ChangeKind, previous: EntitlementValue?, current: EntitlementValue?)] {
        var oldByKey: [[UInt8]: EntitlementValue] = [:]
        var newByKey: [[UInt8]: EntitlementValue] = [:]
        for entry in old.entries { oldByKey[Array(entry.key.utf8)] = entry.value }
        for entry in new.entries { newByKey[Array(entry.key.utf8)] = entry.value }
        let keys = Set(oldByKey.keys).union(newByKey.keys).sorted { $0.lexicographicallyPrecedes($1) }
        return keys.map { key in
            switch (oldByKey[key], newByKey[key]) {
            case let (a?, b?): return (key, a == b ? .unchanged : .changed, a, b)
            case let (a?, nil): return (key, .removed, a, nil)
            case let (nil, b?): return (key, .added, nil, b)
            default: preconditionFailure("key from neither side")
            }
        }
    }

    // MARK: ADAPT-CHANGE-KINDS-MATCH-DONOR

    func test_ADAPT_CHANGE_KINDS_MATCH_DONOR() throws {
        // SPEC-CASE: ADAPT-CHANGE-KINDS-MATCH-DONOR
        let nfc = "caf\u{00E9}"
        let nfd = "cafe\u{0301}"
        XCTAssertEqual(nfc, nfd, "Swift String treats these as canonically equal; the byte keys differ")
        XCTAssertNotEqual(Array(nfc.utf8), Array(nfd.utf8))

        let old = try dictionary([
            ("added.never", .string("only-old-removed")),
            ("bool.vs.int", .boolean(true)),
            ("int.max.vs.unsigned", .integer(Int64.max)),
            ("unsigned.max.vs.negative", .unsignedInteger(UInt64.max)),
            ("real.vs.int", .real(1)),
            ("same.string", .string("same")),
            ("same.array", .array([.boolean(false), .integer(2)])),
            ("same.nested", .dictionary(dictionary([("inner", .integer(1))]))),
            ("changed.nested", .dictionary(dictionary([("inner", .integer(1))]))),
            ("data", .data(Data([1, 2, 3]))),
            (nfc, .string("composed")),
        ])
        let new = try dictionary([
            ("added.new", .boolean(true)),
            ("bool.vs.int", .integer(1)),
            ("int.max.vs.unsigned", .unsignedInteger(UInt64(Int64.max))),
            ("unsigned.max.vs.negative", .integer(-1)),
            ("real.vs.int", .integer(1)),
            ("same.string", .string("same")),
            ("same.array", .array([.boolean(false), .integer(2)])),
            ("same.nested", .dictionary(dictionary([("inner", .integer(1))]))),
            ("changed.nested", .dictionary(dictionary([("inner", .integer(2))]))),
            ("data", .data(Data([1, 2, 3]))),
            (nfd, .string("decomposed")),
        ])

        let result = try CE.ComponentEntitlementComparisonResult(previous: present(old), current: present(new))
        let rows = try XCTUnwrap(result.comparison).rows
        let expected = reference(old, new)

        // Row-for-row agreement with the reference, in byte order, on kind and on both typed values.
        XCTAssertEqual(rows.count, expected.count)
        for (row, want) in zip(rows, expected) {
            XCTAssertEqual(Array(row.key.utf8), want.key, "key order and identity: \(row.key)")
            XCTAssertEqual(row.kind, want.kind, row.key)
            XCTAssertEqual(row.previous, want.previous, row.key)
            XCTAssertEqual(row.current, want.current, row.key)
        }
        // Byte-ordered output with no collapsed keys: both Unicode spellings survive as separate rows.
        let keyBytes = rows.map { Array($0.key.utf8) }
        XCTAssertEqual(keyBytes, keyBytes.sorted { $0.lexicographicallyPrecedes($1) })
        XCTAssertEqual(Set(keyBytes).count, rows.count)
        XCTAssertEqual(keyBytes.filter { $0 == Array(nfc.utf8) || $0 == Array(nfd.utf8) }.count, 2)

        // Named expectations, so a broken reference cannot hide a broken adapter.
        func kind(_ key: String) -> ChangeKind? { rows.first { $0.key.utf8.elementsEqual(key.utf8) }?.kind }
        XCTAssertEqual(kind("added.never"), .removed)
        XCTAssertEqual(kind("added.new"), .added)
        XCTAssertEqual(kind("bool.vs.int"), .changed, "boolean true is not integer 1")
        XCTAssertEqual(kind("int.max.vs.unsigned"), .unchanged, "Int64.max equals the same unsigned value")
        XCTAssertEqual(kind("unsigned.max.vs.negative"), .changed, "UInt64.max is not -1")
        XCTAssertEqual(kind("real.vs.int"), .changed, "real 1 is not integer 1")
        XCTAssertEqual(kind("same.string"), .unchanged)
        XCTAssertEqual(kind("same.array"), .unchanged)
        XCTAssertEqual(kind("same.nested"), .unchanged)
        XCTAssertEqual(kind("changed.nested"), .changed)
        XCTAssertEqual(kind("data"), .unchanged)
        XCTAssertEqual(kind(nfc), .removed)
        XCTAssertEqual(kind(nfd), .added)

        // The adapter passes straight through to the donor type: identical rows to a direct donor comparison.
        let donor = EntitlementComparison(previous: old, current: new)
        XCTAssertEqual(rows.map { $0.kind }, donor.rows.map { $0.kind })
        XCTAssertEqual(rows.map { Array($0.key.utf8) }, donor.rows.map { Array($0.key.utf8) })
        XCTAssertEqual(try XCTUnwrap(result.comparison).changes.count, donor.changes.count)
        XCTAssertEqual(rows.filter { $0.kind == .unchanged }.count, 5)

        // Absent is an empty set against a present side, in either direction; absent against absent has no rows.
        let flat = try dictionary([("a", .boolean(true)), ("b", .string("x"))])
        let toAbsent = try CE.ComponentEntitlementComparisonResult(previous: present(flat), current: absent())
        XCTAssertEqual(toAbsent.comparison?.rows.map { $0.kind }, [.removed, .removed])
        XCTAssertEqual(toAbsent.comparison?.rows.map { $0.key }, ["a", "b"])
        let fromAbsent = try CE.ComponentEntitlementComparisonResult(previous: absent(), current: present(flat))
        XCTAssertEqual(fromAbsent.comparison?.rows.map { $0.kind }, [.added, .added])
        let bothAbsent = try CE.ComponentEntitlementComparisonResult(previous: absent(), current: absent())
        XCTAssertEqual(bothAbsent.comparison?.rows.count, 0)
        let emptyVsEmpty = try CE.ComponentEntitlementComparisonResult(previous: present(dictionary([])), current: present(dictionary([])))
        XCTAssertEqual(emptyVsEmpty.comparison?.rows.count, 0)

        // Either side unavailable gives no comparison at all, never an empty-set comparison.
        for (p, c) in [(try unavailable(), try present(flat)), (try present(flat), try unavailable()),
                       (try unavailable(), try absent()), (try absent(), try unavailable()),
                       (try unavailable(), try unavailable())] {
            let skipped = try CE.ComponentEntitlementComparisonResult(previous: p, current: c)
            XCTAssertNil(skipped.comparison)
        }

        // Typed decoding parity: booleans and integers decode to distinct donor values, so the adapter never merges them.
        let decoded = try FoundationEntitlementDecoder().decode([
            "Flag": NSNumber(value: true),
            "Count": NSNumber(value: 1),
        ] as NSDictionary)
        XCTAssertEqual(decoded["Flag"], .boolean(true))
        XCTAssertEqual(decoded["Count"], .integer(1))
        let parity = try CE.ComponentEntitlementComparisonResult(
            previous: present(dictionary([("k", .boolean(true))])), current: present(dictionary([("k", .integer(1))])))
        XCTAssertEqual(parity.comparison?.changes.map { $0.kind }, [.changed])
    }

    // MARK: ADAPT-ARCHITECTURE-EXPLICIT

    func test_ADAPT_ARCHITECTURE_EXPLICIT() throws {
        // SPEC-CASE: ADAPT-ARCHITECTURE-EXPLICIT

        // RequestedArchitecture: bounded, nonempty, bytes kept exactly.
        expect(.invalidObservation(.emptyArchitecture)) { try CE.RequestedArchitecture(CE.ExactUTF8Key("")) }
        expect(.invalidObservation(.emptyArchitecture)) { try CE.RequestedArchitecture(CE.ExactUTF8Key(String(repeating: "a", count: 256))) }
        let longest = try CE.RequestedArchitecture(CE.ExactUTF8Key(String(repeating: "a", count: 255)))
        XCTAssertEqual(longest.key.bytes.count, 255)
        let requested = try CE.RequestedArchitecture(arm)
        XCTAssertEqual(requested.key, arm)
        XCTAssertEqual(requested, try CE.RequestedArchitecture(CEHarness.key("arm64")))
        XCTAssertNotEqual(requested, try CE.RequestedArchitecture(CEHarness.key("ARM64")), "labels are byte keys, not case folded")
        XCTAssertNotEqual(requested, try CE.RequestedArchitecture(CEHarness.key("arm64e")), "no prefix matching")

        // The snapshot carries the observation's architecture unchanged, and the source slice with it.
        let values = try dictionary([("flag", .boolean(true))])
        let armSnapshot = try present(values, category: .loadCommands, architecture: arm)
        XCTAssertEqual(armSnapshot.architecture, arm)
        XCTAssertEqual(armSnapshot.source?.architecture, arm)
        let infoLike = try present(values, category: .privacy)
        XCTAssertNil(infoLike.architecture, "an architecture-free category stays architecture-free")
        XCTAssertNil(infoLike.source?.architecture)
        XCTAssertEqual(try unavailable(category: .loadCommands, architecture: x86).architecture, x86,
                       "an unavailable slice keeps the architecture that was asked for")

        // Same architecture compares; different architectures never compare, with no first-slice or default fallback.
        let same = try CE.ComponentEntitlementComparisonResult(
            previous: armSnapshot, current: present(dictionary([("flag", .integer(1))]), category: .loadCommands, architecture: arm))
        XCTAssertEqual(same.comparison?.changes.map { $0.kind }, [.changed])
        XCTAssertEqual(same.previous.architecture, arm)
        XCTAssertEqual(same.current.architecture, arm)
        let x86Snapshot = try present(values, category: .loadCommands, architecture: x86)
        expect(.architectureMismatch) { try CE.ComponentEntitlementComparisonResult(previous: armSnapshot, current: x86Snapshot) }
        expect(.architectureMismatch) { try CE.ComponentEntitlementComparisonResult(previous: x86Snapshot, current: armSnapshot) }
        let arm64e = CEHarness.key("arm64e")
        expect(.architectureMismatch) {
            try CE.ComponentEntitlementComparisonResult(previous: armSnapshot,
                                                        current: present(values, category: .loadCommands, architecture: arm64e))
        }
        expect(.architectureMismatch) {
            try CE.ComponentEntitlementComparisonResult(previous: armSnapshot,
                                                        current: present(values, category: .loadCommands, architecture: CEHarness.key("ARM64")))
        }
        // An unavailable side does not excuse a slice mismatch: the architecture check comes before the state check.
        expect(.architectureMismatch) {
            try CE.ComponentEntitlementComparisonResult(previous: unavailable(category: .loadCommands, architecture: arm),
                                                        current: x86Snapshot)
        }
        // Unavailable on the same slice is a result with no comparison, not an error.
        let sameSliceUnavailable = try CE.ComponentEntitlementComparisonResult(
            previous: armSnapshot, current: unavailable(category: .loadCommands, architecture: arm))
        XCTAssertNil(sameSliceUnavailable.comparison)

        // Different categories are never comparable, whatever the architectures.
        let privacy = try present(values, category: .privacy)
        expect(.invalidObservation(.componentMismatch)) {
            try CE.ComponentEntitlementComparisonResult(previous: privacy, current: present(values, category: .loadCommands, architecture: arm))
        }
        expect(.invalidObservation(.componentMismatch)) {
            try CE.ComponentEntitlementComparisonResult(previous: armSnapshot, current: present(values, category: .privacy))
        }
        // A missing architecture against a present one is a mismatch, never a wildcard.
        // A load-command observation cannot even be built without an architecture, so there is no wildcard side.
        expect(.invalidObservation(.emptyArchitecture)) { try present(values, category: .loadCommands, architecture: nil) }
        XCTAssertNotNil(try? CE.ComponentEntitlementComparisonResult(previous: privacy, current: privacy).comparison)
    }
}
