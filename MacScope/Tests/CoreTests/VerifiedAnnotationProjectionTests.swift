import Foundation
import XCTest
@testable import MacScope

@MainActor
enum VerifiedAnnotationTestFixture {
    static let entry: UInt64 = 0x1000
    static let sibling = ImageSlot(rawValue: 1)

    static func store() -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "annotations-\(slot.rawValue)", path: "/tmp/annotations",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        func analysis() -> ImageAnalysis {
            var result = ImageAnalysis()
            result.functions = [FunctionSummary(id: UUID(), name: "entry", startAddress: entry,
                endAddress: entry + 8, confidence: 1)]
            return result
        }
        let snapshot = WorkspaceSnapshot(
            binaries: [image(.primary), image(sibling)],
            analysisBySlot: [.primary: analysis(), sibling: analysis()],
            addressOverrides: [
                .primary(entry): AddressOverride(customName: "before", customComment: "prior comment", tag: "target"),
                .primary(entry + 0x10): AddressOverride(customName: "protected", tag: "other"),
                ImageAddress(slot: sibling, address: entry): AddressOverride(customName: "sibling", customComment: "sibling comment"),
            ])
        return WorkspaceStore(workspaceName: "Verified annotations", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}

/// VA-SCOPE S3 fixtures: a store whose images carry a segment layout, so data addresses can be proven to
/// lie inside a slot segment. Layout: __TEXT [0x0, 0x2000) with the function at 0x1000, __DATA [0x2000, 0x3000).
extension VerifiedAnnotationTestFixture {
    static let dataEntry: UInt64 = 0x2010      // shaped data address, tag, array dataShape
    static let plainData: UInt64 = 0x2020      // no override at baseline
    static let namedData: UInt64 = 0x2030      // named data address
    static let outside: UInt64 = 0x9000        // in no segment

    static func layout() -> MachOPreferredSegmentLayout {
        typealias Record = MachOPreferredSegmentLayout.Record
        // Only the test-built layout; no binary is read or hashed.
        return try! MachOPreferredSegmentLayout(records: [
            Record(name: "__PAGEZERO", preferredVMStart: 0, preferredVMSize: 0, sliceRelativeFileOffset: 0,
                   fileSize: 0, initialProtections: 0),
            Record(name: "__TEXT", preferredVMStart: 0, preferredVMSize: 0x2000, sliceRelativeFileOffset: 0,
                   fileSize: 0x2000, initialProtections: 5),
            Record(name: "__DATA", preferredVMStart: 0x2000, preferredVMSize: 0x1000, sliceRelativeFileOffset: 0x2000,
                   fileSize: 0x1000, initialProtections: 3),
        ], selectedSliceByteCount: 0x4000)
    }

    static func typeDefinitions() -> [TypeDefinition] {
        [TypeDefinition(kind: .struct, name: "Header"), TypeDefinition(kind: .struct, name: "Other"),
         TypeDefinition(kind: .struct, name: "Dup"), TypeDefinition(kind: .struct, name: "Dup")]
    }

    static func typedSnapshot(withLayout: Bool = true) -> WorkspaceSnapshot {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "typed-\(slot.rawValue)", path: "/tmp/typed",
                        kind: "Mach-O executable", architecture: "arm64",
                        preferredSegmentLayout: withLayout ? layout() : nil, slot: slot)
        }
        func analysis() -> ImageAnalysis {
            var result = ImageAnalysis()
            result.functions = [FunctionSummary(id: UUID(), name: "entry", startAddress: entry,
                endAddress: entry + 8, confidence: 1)]
            return result
        }
        return WorkspaceSnapshot(
            binaries: [image(.primary), image(sibling)],
            analysisBySlot: [.primary: analysis(), sibling: analysis()],
            addressOverrides: [
                .primary(entry): AddressOverride(customName: "before", customComment: "prior comment", tag: "target"),
                .primary(entry + 0x10): AddressOverride(customName: "protected", tag: "other"),
                .primary(dataEntry): AddressOverride(tag: "data-tag",
                    dataShape: DataShapeOverride(kind: .array, elementType: "int32_t", elementCount: 4)),
                .primary(namedData): AddressOverride(customName: "named_data"),
                ImageAddress(slot: sibling, address: entry): AddressOverride(customName: "sibling", customComment: "sibling comment"),
            ],
            typeDefinitions: typeDefinitions())
    }

    static func typedStore(withLayout: Bool = true) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "Verified types", snapshot: typedSnapshot(withLayout: withLayout),
                       engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}

final class VerifiedAnnotationProjectionTests: XCTestCase {
    @MainActor
    func testErasingExactlyRequestedFieldReproducesBaseline() throws {
        let store = VerifiedAnnotationTestFixture.store()
        let before = try store.readAnnotationProjection(at: .primary(0x1000))
        for field in VerifiedAnnotationField.allCases {
            var after = before
            field.set("new value", in: &after.target)
            XCTAssertNil(after.mismatch(comparedTo: before, field: field, requested: "new value"))
            after.target.tag = "collateral"
            XCTAssertEqual(after.mismatch(comparedTo: before, field: field, requested: "new value"), .protectedFields)
            XCTAssertEqual(after.mismatch(comparedTo: before, field: field, requested: "not written"), .readback)
        }
    }

    @MainActor
    func testDigestIncludesOtherOverrideFieldsAndSessionOnlyAuthority() throws {
        let store = VerifiedAnnotationTestFixture.store()
        let before = try store.readAnnotationProjection(at: .primary(0x1000))
        store.setCustomComment(0x1010, in: .primary, comment: "collateral")
        let changed = try store.readAnnotationProjection(at: .primary(0x1000))
        XCTAssertNotEqual(changed.protectedDigest, before.protectedDigest)
        var copy = store.snapshot
        copy.addressOverrides[.primary(0x1010)]?.ownReturnAuthorityFile = "session-source"
        let sessionChanged = try NativeAnnotationProjection(snapshot: copy, key: .primary(0x1000))
        XCTAssertNotEqual(sessionChanged.protectedDigest, changed.protectedDigest)
    }

    @MainActor
    func testDigestIsIndependentOfDictionaryOrderAndScopedToSlot() throws {
        let store = VerifiedAnnotationTestFixture.store()
        let before = try store.readAnnotationProjection(at: .primary(0x1000))
        var copy = store.snapshot
        copy.addressOverrides = Dictionary(uniqueKeysWithValues: copy.addressOverrides.reversed())
        XCTAssertEqual(try NativeAnnotationProjection(snapshot: copy, key: .primary(0x1000)), before)
        store.setCustomName(0x1000, in: VerifiedAnnotationTestFixture.sibling, name: "sibling change")
        XCTAssertEqual(try store.readAnnotationProjection(at: .primary(0x1000)), before)
    }

    // MARK: VA-SCOPE S3: stamp (ruling 3, T4 and T5) through the production projector

    @MainActor
    private func stamp(_ overrides: [ImageAddress: AddressOverride]) throws -> VAProjectionStamp {
        let snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:], addressOverrides: overrides)
        return try NativeAnnotationProjector().stamp(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
                                                     snapshot: snapshot, revision: 0)
    }

    /// T4. The same two states and digests as VerifiedFieldClassCodecTests.testGoldenNameCommentStampsAreUnchanged
    /// (computed on main before S3), reproduced by the production projector, both as a bare digest and as the
    /// stamp a snapshot produces. An empty applied-type name is the same as none and must not move them.
    @MainActor
    func testNameCommentStatesKeepTheV1GoldenDigestsThroughTheProductionProjector() throws {
        let sibling = ImageSlot(rawValue: 1)
        let first: [ImageAddress: AddressOverride] = [
            .primary(0x1000): AddressOverride(customName: "alpha", customComment: "first comment"),
            .primary(0x2000): AddressOverride(customName: "beta"),
            ImageAddress(slot: sibling, address: 0x1000): AddressOverride(customComment: "sibling note"),
            .primary(0x3000): AddressOverride(tag: "ignored: no name or comment"),
        ]
        let second: [ImageAddress: AddressOverride] = [
            .primary(0x40): AddressOverride(customName: "ns/entry \"main\" é", customComment: "line one\nline two"),
            ImageAddress(slot: ImageSlot(rawValue: 2), address: 0xFFFF_FFFF_0000): AddressOverride(customComment: "tail"),
            .primary(0x10): AddressOverride(customName: "only-name"),
        ]
        let goldenFirst = "1b8c2c91648f746515c861e81f8875a4d0322e2f126ac34b0bcec35186f6ce84"
        let goldenSecond = "9e3f6adf083d2264f7da169fac7f1eca1442ca9b13294186611b1f88a49d4e33"
        XCTAssertEqual(NativeAnnotationProjector.digest(first), goldenFirst)
        XCTAssertEqual(NativeAnnotationProjector.digest(second), goldenSecond)
        XCTAssertEqual(try stamp(first).digest, goldenFirst)
        XCTAssertEqual(try stamp(second).digest, goldenSecond)
        XCTAssertEqual(NativeAnnotationProjector.domain, "com.jeff.macscope.verified-annotation-projection.v1")
        var withEmptyType = first
        withEmptyType[.primary(0x3000)] = AddressOverride(tag: "ignored: no name or comment", appliedTypeName: "")
        withEmptyType[.primary(0x2000)]?.appliedTypeName = ""
        XCTAssertEqual(NativeAnnotationProjector.digest(withEmptyType), goldenFirst)
    }

    /// T5. A type change moves the stamp through the production projector (not the full-override-map
    /// fixture), a clear restores it, and fields the stamp does not bind do not move it.
    @MainActor
    func testTypeChangeMovesTheStampThroughTheProductionProjector() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let workspaceID = UUID(), documentID = UUID(), installationID = UUID()
        func digest(_ snapshot: WorkspaceSnapshot) throws -> String {
            try NativeAnnotationProjector().stamp(workspaceID: workspaceID, documentID: documentID,
                installationID: installationID, snapshot: snapshot, revision: 3).digest
        }
        let base = try digest(store.snapshot)
        let key = ImageAddress.primary(VerifiedAnnotationTestFixture.plainData)

        var typed = store.snapshot
        typed.addressOverrides[key] = AddressOverride(appliedTypeName: "Header")
        let withHeader = try digest(typed)
        XCTAssertNotEqual(withHeader, base, "a type on an address with no other annotation must move the stamp")

        typed.addressOverrides[key]?.appliedTypeName = "Other"
        let withOther = try digest(typed)
        XCTAssertNotEqual(withOther, withHeader, "a different type name must move the stamp")

        // Type next to a name on the same address, and a type on a named address.
        var named = store.snapshot
        let named0 = try digest(named)
        named.addressOverrides[.primary(VerifiedAnnotationTestFixture.namedData)]?.appliedTypeName = "Header"
        XCTAssertNotEqual(try digest(named), named0)

        typed.addressOverrides[key] = nil
        XCTAssertEqual(try digest(typed), base, "clearing the type restores the stamp")

        // Not bound by the stamp: tag and data shape. This is the existing stamp scope, unchanged.
        var unbound = store.snapshot
        unbound.addressOverrides[.primary(VerifiedAnnotationTestFixture.dataEntry)]?.tag = "different"
        unbound.addressOverrides[.primary(VerifiedAnnotationTestFixture.dataEntry)]?.dataShape =
            DataShapeOverride(kind: .alignment, alignment: 8)
        XCTAssertEqual(try digest(unbound), base)
    }

    /// The v1 stamp bytes: a typed entry adds a `type` key and nothing else; untyped entries have none.
    func testTypeKeyIsOmittedWhenNilAndPresentWhenSet() throws {
        let plain = NativeAnnotationProjector.digest([.primary(0x10): AddressOverride(customName: "n")])
        let typed = NativeAnnotationProjector.digest([.primary(0x10): AddressOverride(customName: "n", appliedTypeName: "T")])
        XCTAssertNotEqual(plain, typed)
        XCTAssertEqual(NativeAnnotationProjector.digest([.primary(0x10): AddressOverride(customName: "n", appliedTypeName: "")]), plain)
        // Recompute the typed digest from the documented bytes to pin the key name and placement.
        let bytes = Data(#"{"domain":"com.jeff.macscope.verified-annotation-projection.v1","entries":[{"address":16,"name":"n","slot":0,"type":"T"}]}"#.utf8)
        XCTAssertEqual(typed, VerifiedAnnotationAuditCodec.sha256Hex(bytes))
        let plainBytes = Data(#"{"domain":"com.jeff.macscope.verified-annotation-projection.v1","entries":[{"address":16,"name":"n","slot":0}]}"#.utf8)
        XCTAssertEqual(plain, VerifiedAnnotationAuditCodec.sha256Hex(plainBytes))
    }

    // MARK: Type erase rule on the transient projection

    @MainActor
    func testTypeEraseRuleResetsOnlyTheAppliedTypeAndKeepsDataShapeProtected() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let shaped = ImageAddress.primary(VerifiedAnnotationTestFixture.dataEntry)
        let before = try store.readAnnotationProjection(at: shaped)
        var after = before
        after.target.appliedTypeName = "Header"
        XCTAssertNil(after.typeMismatch(comparedTo: before, requested: "Header"))
        XCTAssertEqual(after.typeMismatch(comparedTo: before, requested: "Other"), .readback)
        var shapeChanged = after
        shapeChanged.target.dataShape = DataShapeOverride(kind: .alignment, alignment: 8)
        XCTAssertEqual(shapeChanged.typeMismatch(comparedTo: before, requested: "Header"), .protectedFields)
        var tagChanged = after
        tagChanged.target.tag = "collateral"
        XCTAssertEqual(tagChanged.typeMismatch(comparedTo: before, requested: "Header"), .protectedFields)
    }

    // MARK: VA-SCOPE S6a: signature stamp and erase rule

    private func sig(_ rows: [(String, String, String)], returnType: String? = "int") -> FunctionSignatureOverride {
        FunctionSignatureOverride(returnType: returnType, args: rows.map { ArgOverride(rowToken: $0.0, name: $0.1, type: $0.2) })
    }

    /// T5, signature half: a type or signature edit changes the v2 stamp, tested against the production projector.
    /// (The domain stays v1 by ruling 3; the `signature` key is what moves the stamp.)
    @MainActor
    func testSignatureChangeMovesTheStampThroughTheProductionProjector() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let workspaceID = UUID(), documentID = UUID(), installationID = UUID()
        func digest(_ snapshot: WorkspaceSnapshot) throws -> String {
            try NativeAnnotationProjector().stamp(workspaceID: workspaceID, documentID: documentID,
                installationID: installationID, snapshot: snapshot, revision: 3).digest
        }
        let base = try digest(store.snapshot)
        let entry = ImageAddress.primary(VerifiedAnnotationTestFixture.entry)
        var edited = store.snapshot
        edited.addressOverrides[entry]?.signature = sig([("a", "x", "int")])
        let first = try digest(edited)
        XCTAssertNotEqual(first, base, "a signature on an annotated function must move the stamp")
        edited.addressOverrides[entry]?.signature = sig([("a", "x", "long")])
        let second = try digest(edited)
        XCTAssertNotEqual(second, first, "a different parameter type must move the stamp")
        edited.addressOverrides[entry]?.signature = sig([("a", "x", "long")], returnType: "void")
        XCTAssertNotEqual(try digest(edited), second, "a different return type must move the stamp")
        edited.addressOverrides[entry]?.signature = FunctionSignatureOverride(returnType: "int", noReturnState: .noReturn)
        XCTAssertNotEqual(try digest(edited), first)
        // rowToken is not part of the canonical form (ruling 7), so a token-only change keeps the stamp.
        edited.addressOverrides[entry]?.signature = sig([("a", "x", "long")])
        let tokenA = try digest(edited)
        edited.addressOverrides[entry]?.signature = sig([("zzz", "x", "long")])
        XCTAssertEqual(try digest(edited), tokenA)
        // A signature on an address with no other annotation also moves it; clearing restores the base.
        var lone = store.snapshot
        let bare = ImageAddress.primary(0x1020)
        lone.addressOverrides[bare] = AddressOverride(signature: sig([("a", "x", "int")]))
        XCTAssertNotEqual(try digest(lone), base)
        lone.addressOverrides[bare] = nil
        XCTAssertEqual(try digest(lone), base)
        edited.addressOverrides[entry]?.signature = nil
        XCTAssertEqual(try digest(edited), base, "clearing the signature restores the stamp")
        // Session authority is not bound by the stamp.
        edited.addressOverrides[entry]?.ownReturnAuthorityFile = "session-authority"
        XCTAssertEqual(try digest(edited), base)
    }

    /// The v1 stamp bytes: a signature adds a `signature` key holding the canonical string and nothing else;
    /// unsigned entries have none, so the name/comment/type digests are unchanged.
    func testSignatureKeyIsOmittedWhenNilAndPinnedWhenSet() throws {
        let value = sig([("a", "x", "int")])
        let text = try VerifiedFieldCodec.canonicalSignature(value)
        let quoted = try VACanonicalJSON.encode([text])
        let literal = String(decoding: quoted, as: UTF8.self).dropFirst().dropLast()
        let plain = NativeAnnotationProjector.digest([.primary(0x10): AddressOverride(customName: "n")])
        let signed = NativeAnnotationProjector.digest([.primary(0x10): AddressOverride(customName: "n", signature: value)])
        XCTAssertNotEqual(plain, signed)
        let bytes = Data("{\"domain\":\"com.jeff.macscope.verified-annotation-projection.v1\",\"entries\":[{\"address\":16,\"name\":\"n\",\"signature\":\(literal),\"slot\":0}]}".utf8)
        XCTAssertEqual(signed, VerifiedAnnotationAuditCodec.sha256Hex(bytes))
        let plainBytes = Data(#"{"domain":"com.jeff.macscope.verified-annotation-projection.v1","entries":[{"address":16,"name":"n","slot":0}]}"#.utf8)
        XCTAssertEqual(plain, VerifiedAnnotationAuditCodec.sha256Hex(plainBytes))
        // (a) The type digest is unchanged by the new key.
        let typed = NativeAnnotationProjector.digest([.primary(0x10): AddressOverride(customName: "n", appliedTypeName: "T")])
        let typedBytes = Data(#"{"domain":"com.jeff.macscope.verified-annotation-projection.v1","entries":[{"address":16,"name":"n","slot":0,"type":"T"}]}"#.utf8)
        XCTAssertEqual(typed, VerifiedAnnotationAuditCodec.sha256Hex(typedBytes))
    }

    /// S6a gap 7(i): a signature that cannot be canonicalised still moves the stamp (fail closed) through the
    /// `unencodable:` fallback, distinct per value, and the commit-side class read uses the same rule.
    func testUnencodableSignatureStillMovesTheStamp() throws {
        let bad = sig([("a", "x", String(repeating: "t", count: 513))])
        let otherBad = sig([("a", "x", String(repeating: "u", count: 513))])
        XCTAssertThrowsError(try VerifiedFieldCodec.canonicalSignature(bad))
        XCTAssertThrowsError(try VerifiedFieldCodec.canonicalSignature(otherBad))
        let key = ImageAddress.primary(0x10)
        let plain = NativeAnnotationProjector.digest([key: AddressOverride(customName: "n")])
        let first = NativeAnnotationProjector.digest([key: AddressOverride(customName: "n", signature: bad)])
        let second = NativeAnnotationProjector.digest([key: AddressOverride(customName: "n", signature: otherBad)])
        XCTAssertNotEqual(first, plain, "an unencodable signature must still move the stamp")
        XCTAssertNotEqual(first, second, "different unencodable signatures must stamp differently")
        XCTAssertNotEqual(NativeAnnotationProjector.digest([key: AddressOverride(signature: bad)]),
                          NativeAnnotationProjector.digest([:]), "a bare unencodable signature is not omitted")
        XCTAssertEqual(first, NativeAnnotationProjector.digest([key: AddressOverride(customName: "n", signature: bad)]),
                       "the fallback is deterministic")
        // The class read (key-level CAS, raw leg) maps the same value to a string no canonical text can equal.
        let read = try XCTUnwrap(VerifiedFieldClass.functionSignature.value(in: AddressOverride(signature: bad)))
        XCTAssertTrue(read.hasPrefix("unencodable:"))
        XCTAssertNotEqual(read, VerifiedFieldClass.functionSignature.value(in: AddressOverride(signature: otherBad)))
        XCTAssertThrowsError(try VerifiedFieldCodec.decodeSignature(read), "an unencodable marker is never decodable")
    }

    /// T10: signature erase rule accepts only the `ownReturnAuthorityFile` reset as extra drift.
    @MainActor
    func testSignatureEraseRuleAcceptsOnlyTheAuthorityResetAsExtraDrift() throws {
        let entry = ImageAddress.primary(VerifiedAnnotationTestFixture.entry)
        let base = sig([("a", "x", "int")])
        let next = sig([("a", "x", "long")])
        let store = VerifiedAnnotationTestFixture.typedStore()
        var live = try XCTUnwrap(store.snapshot.addressOverrides[entry])
        live.signature = base
        live.ownReturnAuthorityFile = "session-authority"
        store.applyOverride(entry, live, actionName: "fixture")
        let before = try store.readAnnotationProjection(at: entry)
        XCTAssertEqual(before.target.ownReturnAuthorityFile, "session-authority")

        // Accepted: the signature changes and the didSet reset of the authority rides along.
        var changed = before
        changed.target.signature = next
        XCTAssertNil(changed.target.ownReturnAuthorityFile)
        XCTAssertNil(changed.signatureMismatch(comparedTo: before, requested: next))
        XCTAssertTrue(VerifiedAnnotationAuditFieldClass.functionSignature
            .fieldClassMatches(previous: before.target, new: changed.target))
        // Readback is by canonical form: a different request than what was stored is a readback failure.
        XCTAssertEqual(changed.signatureMismatch(comparedTo: before, requested: base), .readback)
        XCTAssertEqual(changed.signatureMismatch(comparedTo: before, requested: nil), .readback)
        // Refused: a different non-nil authority beside the change is not the reset.
        var otherAuthority = changed
        otherAuthority.target.ownReturnAuthorityFile = "other-authority"
        XCTAssertEqual(otherAuthority.signatureMismatch(comparedTo: before, requested: next), .protectedFields)
        // Refused: an authority change with no signature change, in both directions.
        for authority in [nil, "other-authority"] as [String?] {
            var authorityOnly = before
            authorityOnly.target.ownReturnAuthorityFile = authority
            XCTAssertEqual(authorityOnly.signatureMismatch(comparedTo: before, requested: base), .protectedFields,
                           "authority \(authority ?? "nil") without a signature change")
        }
        // Refused: any other member beside the signature change.
        var tag = changed
        tag.target.tag = "collateral"
        XCTAssertEqual(tag.signatureMismatch(comparedTo: before, requested: next), .protectedFields)
        var type = changed
        type.target.appliedTypeName = "Header"
        XCTAssertEqual(type.signatureMismatch(comparedTo: before, requested: next), .protectedFields)
        var name = changed
        name.target.customName = "collateral"
        XCTAssertEqual(name.signatureMismatch(comparedTo: before, requested: next), .protectedFields)
        // Clear: nil requested, signature gone, authority reset.
        var cleared = before
        cleared.target.signature = nil
        XCTAssertNil(cleared.signatureMismatch(comparedTo: before, requested: nil))
        XCTAssertEqual(cleared.signatureMismatch(comparedTo: before, requested: base), .readback)
    }

    /// Ruling 7 at the projection: a rowToken-only change reads back as equal and is erased with the authority
    /// reset at the target, but the same churn at any other address is protected drift.
    @MainActor
    func testRowTokenOnlyChangeIsNoOpForReadbackAndProtectedDriftElsewhere() throws {
        let entry = ImageAddress.primary(VerifiedAnnotationTestFixture.entry)
        let other = ImageAddress.primary(VerifiedAnnotationTestFixture.entry + 0x10)
        let old = sig([("old-1", "x", "int")])
        let retokened = sig([("new-1", "x", "int")])
        let store = VerifiedAnnotationTestFixture.typedStore()
        var live = try XCTUnwrap(store.snapshot.addressOverrides[entry])
        live.signature = old
        live.ownReturnAuthorityFile = "session-authority"
        store.applyOverride(entry, live, actionName: "fixture")
        var neighbor = try XCTUnwrap(store.snapshot.addressOverrides[other])
        neighbor.signature = old
        store.applyOverride(other, neighbor, actionName: "fixture")
        let before = try store.readAnnotationProjection(at: entry)

        var targetRetokened = before
        targetRetokened.target.signature = retokened
        XCTAssertNil(targetRetokened.target.ownReturnAuthorityFile)
        XCTAssertNil(targetRetokened.signatureMismatch(comparedTo: before, requested: retokened))
        XCTAssertNil(targetRetokened.signatureMismatch(comparedTo: before, requested: old),
                     "observed equals requested by canonical form, whichever tokens the request carries")

        var snapshot = store.snapshot
        snapshot.addressOverrides[other]?.signature = retokened
        let neighborRetokened = try NativeAnnotationProjection(snapshot: snapshot, key: entry)
        XCTAssertNotEqual(neighborRetokened.protectedDigest, before.protectedDigest)
        XCTAssertEqual(neighborRetokened.signatureMismatch(comparedTo: before, requested: old), .protectedFields)
    }

    // MARK: addressFacts entry producer

    @MainActor
    func testAddressFactsEntryDescribesDataAndFunctionAddresses() throws {
        let store = VerifiedAnnotationTestFixture.typedStore()
        let data = try NativeAddressFacts.entry(snapshot: store.snapshot, key: .primary(VerifiedAnnotationTestFixture.dataEntry))
        XCTAssertEqual(data, VAAddressProjection(address: VAAddress64(0x2010), segment: "__DATA", isFunctionEntry: false))
        let function = try NativeAddressFacts.entry(snapshot: store.snapshot, key: .primary(0x1000))
        XCTAssertEqual(function, VAAddressProjection(address: VAAddress64(0x1000), segment: "__TEXT", isFunctionEntry: true))
        // A forced procedure start counts as a function entry even before reanalysis finds it.
        var forced = store.snapshot
        forced.addressOverrides[.primary(0x2020)] = AddressOverride(markAsProcedure: true)
        XCTAssertTrue(try NativeAddressFacts.entry(snapshot: forced, key: .primary(0x2020)).isFunctionEntry)
        // Baseline applied type rides in the entry.
        var typed = store.snapshot
        typed.addressOverrides[.primary(0x2020)] = AddressOverride(appliedTypeName: "Header")
        XCTAssertEqual(try NativeAddressFacts.entry(snapshot: typed, key: .primary(0x2020)).appliedTypeName, "Header")
    }

    @MainActor
    func testAddressFactsEntryRefusesAddressesOutsideEverySegmentAndMissingLayouts() throws {
        func code(_ snapshot: WorkspaceSnapshot, _ address: UInt64) -> VerifiedAnnotationFailure.Code? {
            do { _ = try NativeAddressFacts.entry(snapshot: snapshot, key: .primary(address)); return nil }
            catch { return (error as? VerifiedCandidateError)?.code }
        }
        let snapshot = VerifiedAnnotationTestFixture.typedSnapshot()
        XCTAssertEqual(code(snapshot, VerifiedAnnotationTestFixture.outside), .addressOutsideSegments)
        XCTAssertEqual(code(snapshot, 0x3000), .addressOutsideSegments, "one past the end of __DATA")
        XCTAssertNil(code(snapshot, 0x2FFF), "last byte of __DATA")
        // __PAGEZERO and a zero-sized segment never own an address.
        XCTAssertEqual(code(snapshot, 0x0), nil, "__TEXT starts at 0 and owns it; __PAGEZERO is skipped")
        // A slot with no segment layout cannot prove containment.
        XCTAssertEqual(code(VerifiedAnnotationTestFixture.typedSnapshot(withLayout: false), 0x2010), .addressOutsideSegments)
        // A slot with no binary at all.
        XCTAssertEqual(code(WorkspaceSnapshot(binaries: [], analysisBySlot: [:]), 0x2010), .addressOutsideSegments)
    }

    // MARK: Coordinator: addressType resolves through the new projection entry (C10)

    private func addressProjection(revision: UInt64 = 1) -> VAWorkspaceProjection {
        VAWorkspaceProjection(workspaceID: UUID(), documentID: UUID(), installationID: UUID(), revision: revision,
            components: [VAComponentProjection(id: UUID(), imageSlot: 0,
                binarySHA256: String(repeating: "a", count: 64), sliceSHA256: String(repeating: "b", count: 64),
                architecture: .arm64, analysisIdentity: "s3-test",
                functions: [VAFunctionProjection(address: VAAddress64(0x1000), originalName: "entry", disassembly: "ret")],
                addresses: [
                    VAAddressProjection(address: VAAddress64(0x1000), segment: "__TEXT", isFunctionEntry: true),
                    VAAddressProjection(address: VAAddress64(0x2010), segment: "__DATA", isFunctionEntry: false),
                ])])
    }

    private func target(_ projection: VAWorkspaceProjection, _ address: UInt64) -> VATargetReference {
        VATargetReference(componentID: projection.components[0].id, function: VAAddress64(address))
    }

    func testProjectionWithoutAddressEntriesKeepsItsEncodingAndValidatesEntries() throws {
        var plain = addressProjection()
        plain.components[0].addresses = nil
        XCTAssertFalse(String(decoding: try VACanonicalJSON.encode(plain), as: UTF8.self).contains("addresses"))
        XCTAssertNoThrow(try addressProjection().validate())
        XCTAssertNotEqual(try addressProjection().stamp().digest, try plain.stamp().digest)
        var duplicate = addressProjection()
        duplicate.components[0].addresses?.append(VAAddressProjection(address: VAAddress64(0x2010), segment: "__DATA", isFunctionEntry: false))
        XCTAssertThrowsError(try duplicate.validate())
        var inconsistent = addressProjection()
        inconsistent.components[0].addresses?[0] = VAAddressProjection(address: VAAddress64(0x1000), segment: "__TEXT", isFunctionEntry: false)
        XCTAssertThrowsError(try inconsistent.validate(), "a listed function must be flagged as a function entry")
        var badSegment = addressProjection()
        badSegment.components[0].addresses?[1] = VAAddressProjection(address: VAAddress64(0x2010), segment: "", isFunctionEntry: false)
        XCTAssertThrowsError(try badSegment.validate())
        var badType = addressProjection()
        badType.components[0].addresses?[1] = VAAddressProjection(address: VAAddress64(0x2010), segment: "__DATA",
            isFunctionEntry: false, appliedTypeName: String(repeating: "t", count: 257))
        XCTAssertThrowsError(try badType.validate())
    }

    func testCoordinatorInspectsADataAddressThroughTheEntryAndRefusesTheRest() async throws {
        let projection = addressProjection()
        let backend = AddressFactsTestBackend(projection: projection)
        let coordinator = VAVerificationCoordinator(backend: backend)
        let data = target(projection, 0x2010)
        let record = try await coordinator.inspect(data, kind: .addressFacts)
        XCTAssertEqual(record.observation.query, .addressFacts)
        XCTAssertEqual(record.observation.target, data)
        let stored = try await backend.load()
        XCTAssertEqual(stored.state.evidence.map(\.id), [record.id])
        XCTAssertNoThrow(try stored.state.validate(), "evidence for a data address must survive state validation")

        func refusal(_ address: UInt64, _ kind: VAQueryKind) async -> VAVerificationError? {
            do { _ = try await coordinator.inspect(target(projection, address), kind: kind); return nil }
            catch { return error as? VAVerificationError }
        }
        let functionEntry = await refusal(0x1000, .addressFacts)
        XCTAssertEqual(functionEntry, .functionEntryTarget)
        // Negative: an address outside every segment has no entry, so it is not a known target.
        let outside = await refusal(VerifiedAnnotationTestFixture.outside, .addressFacts)
        XCTAssertEqual(outside, .unknownTarget)
        // The function-only rule still holds for every other query kind.
        let wrongKind = await refusal(0x2010, .disassembly)
        XCTAssertEqual(wrongKind, .unknownTarget)
        let functionDisassembly = await refusal(0x1000, .disassembly)
        XCTAssertNil(functionDisassembly)
    }

    func testCoordinatorResolvesAnAddressTypeTargetWithoutUnknownTarget() async throws {
        let projection = addressProjection()
        let backend = AddressFactsTestBackend(projection: projection)
        let coordinator = VAVerificationCoordinator(backend: backend)
        let base = try projection.stamp()
        let evidence = try await coordinator.inspect(target(projection, 0x2010), kind: .addressFacts)

        func receipt(_ address: UInt64, evidenceIDs: [UUID]) async throws -> VAVerificationReceipt {
            let request = VAMutationRequest(base: base, edits: [VAEditIntent(target: target(projection, address),
                kind: .addressType, value: "Header", evidenceIDs: evidenceIDs)], rationale: "S3 target resolution")
            return try await coordinator.execute(request)
        }
        // Data address: resolved through the entry, so the request reaches staging. The portable verifier then
        // refuses the new kind (S4 owns the native verifier), which is a typed unsupportedMutation.
        let resolved = try await receipt(0x2010, evidenceIDs: [evidence.id])
        XCTAssertEqual(resolved.decision, .rejected)
        XCTAssertEqual(resolved.failure, "unsupportedMutation")
        let stageCallsAfterData = await backend.stageCalls
        XCTAssertEqual(stageCallsAfterData, 1)
        // Function entry: typed refusal before staging.
        let functionEntry = try await receipt(0x1000, evidenceIDs: [UUID()])
        XCTAssertEqual(functionEntry.failure, "functionEntryTarget")
        // Negative: outside every segment, no entry: unknownTarget, before staging.
        let outside = try await receipt(VerifiedAnnotationTestFixture.outside, evidenceIDs: [UUID()])
        XCTAssertEqual(outside.failure, "unknownTarget")
        let stageCalls = await backend.stageCalls
        XCTAssertEqual(stageCalls, 1, "neither refusal may reach the backend")
    }

    func testUnconfiguredBackendCannotRunVerifiedMutation() async throws {
        let projection = VAWorkspaceProjection(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
            components: [VAComponentProjection(id: UUID(), imageSlot: 0,
                binarySHA256: String(repeating: "a", count: 64), sliceSHA256: String(repeating: "b", count: 64),
                architecture: .arm64, analysisIdentity: "test-generation",
                functions: [VAFunctionProjection(address: VAAddress64(0x1000), originalName: "entry", disassembly: "ret")])])
        let backend = UnconfiguredAnnotationTestBackend(projection: projection)
        let target = VATargetReference(componentID: projection.components[0].id, function: VAAddress64(0x1000))
        let request = VAMutationRequest(base: try projection.stamp(),
            edits: [VAEditIntent(target: target, kind: .functionName, value: "refused", evidenceIDs: [UUID()])],
            rationale: "Exercise the closed capability gate")
        let receipt = try await VAVerificationCoordinator(backend: backend).execute(request)
        XCTAssertFalse(NativeIntegrationGate.unconfigured.supportsVerifiedMutation)
        XCTAssertEqual(receipt.decision, .rejected)
        XCTAssertEqual(receipt.mechanical, .notVerified)
        XCTAssertEqual(receipt.failure, "unsupportedPublication")
        let snapshot = try await backend.load()
        XCTAssertEqual(snapshot.state.projection, projection)
        let stageCalls = await backend.stageCalls
        XCTAssertEqual(stageCalls, 0)
    }
}

private actor UnconfiguredAnnotationTestBackend: VAVerificationBackend {
    nonisolated let capabilities = NativeIntegrationGate.unconfigured
    private var state: VAVerificationState
    private(set) var stageCalls = 0
    init(projection: VAWorkspaceProjection) { state = VAVerificationState(projection: projection) }
    func load() throws -> VABackendSnapshot { VABackendSnapshot(state: state, version: "test-only") }
    func observe(_ target: VATargetReference, kind: VAQueryKind, at stamp: VAProjectionStamp) throws -> VAEvidenceRecord {
        throw VAVerificationError.unsupportedPublication
    }
    func stage(_ edits: [VAEditIntent], against baseline: VAWorkspaceProjection) throws -> VAWorkspaceProjection {
        stageCalls += 1
        throw VAVerificationError.unsupportedPublication
    }
    func publish(_ state: VAVerificationState, expecting version: String) throws -> VABackendSnapshot {
        // Rejected audit records are permitted in this in-memory test backend; annotation
        // publication is refused independently even if the coordinator gate regresses.
        guard state.projection == self.state.projection else { throw VAVerificationError.unsupportedPublication }
        self.state = state
        return try load()
    }
}

/// In-memory backend with the full capability set so the coordinator's target resolution is reachable.
/// `observe` returns complete addressFacts evidence; `stage` records the call and returns the baseline.
private actor AddressFactsTestBackend: VAVerificationBackend {
    nonisolated let capabilities = VABackendCapabilities(isolatedCandidates: true, independentCandidateReadback: true,
        atomicStateAndReceiptPublication: true, compareAndSwapPublication: true)
    private var state: VAVerificationState
    private var version = 0
    private(set) var stageCalls = 0
    init(projection: VAWorkspaceProjection) { state = VAVerificationState(projection: projection) }
    func load() throws -> VABackendSnapshot { VABackendSnapshot(state: state, version: "v\(version)") }
    func observe(_ target: VATargetReference, kind: VAQueryKind, at stamp: VAProjectionStamp) throws -> VAEvidenceRecord {
        VAEvidenceRecord(id: UUID(), observation: VANativeObservation(stamp: stamp, target: target, query: kind,
            completeness: .complete, content: "address facts"), capturedAt: Date(timeIntervalSince1970: 1))
    }
    func stage(_ edits: [VAEditIntent], against baseline: VAWorkspaceProjection) throws -> VAWorkspaceProjection {
        stageCalls += 1
        return baseline
    }
    func publish(_ state: VAVerificationState, expecting version: String) throws -> VABackendSnapshot {
        guard version == "v\(self.version)" else { throw VAVerificationError.staleProjection }
        self.state = state
        self.version += 1
        return try load()
    }
}
