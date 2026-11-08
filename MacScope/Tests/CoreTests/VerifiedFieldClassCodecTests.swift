import Foundation
import XCTest
@testable import MacScope

// VA-SCOPE slice S1: Core edit kinds, field classes and value codecs. Synthetic only.
final class VerifiedFieldClassCodecTests: XCTestCase {
    // MARK: Fixtures

    private let workspaceID = UUID(), documentID = UUID(), installationID = UUID(), componentID = UUID()
    private let functionAddress = VAAddress64(0x4000)

    private func stamp(_ revision: UInt64) -> VAProjectionStamp {
        VAProjectionStamp(workspaceID: workspaceID, documentID: documentID, installationID: installationID,
                          revision: revision, digest: String(repeating: "a", count: 64))
    }

    private var target: VATargetReference { VATargetReference(componentID: componentID, function: functionAddress) }

    private func request(_ kind: VAEditKind, _ value: String?) -> VAMutationRequest {
        VAMutationRequest(base: stamp(0), edits: [VAEditIntent(target: target, kind: kind, value: value, evidenceIDs: [UUID()])],
                          rationale: "S1 test")
    }

    private func projection(revision: UInt64 = 1) -> VAWorkspaceProjection {
        VAWorkspaceProjection(
            workspaceID: workspaceID, documentID: documentID, installationID: installationID, revision: revision,
            components: [VAComponentProjection(
                id: componentID, imageSlot: 0, binarySHA256: String(repeating: "b", count: 64),
                sliceSHA256: String(repeating: "c", count: 64), architecture: .arm64, analysisIdentity: "s1-test",
                functions: [VAFunctionProjection(address: functionAddress, originalName: "f", disassembly: "ret")])])
    }

    private func assertShape(_ kind: VAEditKind, _ value: String?, accepted: Bool,
                             _ message: String, file: StaticString = #filePath, line: UInt = #line) {
        let req = request(kind, value)
        if accepted {
            XCTAssertNoThrow(try req.validateShape(), message, file: file, line: line)
        } else {
            XCTAssertThrowsError(try req.validateShape(), message, file: file, line: line)
        }
    }

    // MARK: (a) validateShape for the new kinds

    func testAddressTypeShapeBoundsAndCharacters() {
        assertShape(.addressType, nil, accepted: true, "nil clears")
        assertShape(.addressType, "T", accepted: true, "short name")
        assertShape(.addressType, String(repeating: "a", count: 256), accepted: true, "256 bytes")
        assertShape(.addressType, String(repeating: "a", count: 257), accepted: false, "257 bytes")
        // Bytes, not characters: 128 two-byte scalars fit, 129 do not.
        assertShape(.addressType, String(repeating: "é", count: 128), accepted: true, "128 x 2 bytes")
        assertShape(.addressType, String(repeating: "é", count: 129), accepted: false, "129 x 2 bytes")
        assertShape(.addressType, "", accepted: false, "empty")
        assertShape(.addressType, " \t ", accepted: false, "blank")
        assertShape(.addressType, "a\nb", accepted: false, "LF")
        assertShape(.addressType, "a\rb", accepted: false, "CR")
        assertShape(.addressType, "a\0b", accepted: false, "NUL")
        XCTAssertThrowsError(try request(.addressType, "a\nb").validateShape()) {
            XCTAssertEqual($0 as? VAVerificationError, .invalidRequest("invalid address type"))
        }
    }

    func testFunctionPrototypeShapeBoundsAreBoundsOnly() {
        assertShape(.functionPrototype, nil, accepted: true, "nil clears")
        assertShape(.functionPrototype, String(repeating: "x", count: 16_384), accepted: true, "16384 bytes")
        assertShape(.functionPrototype, String(repeating: "x", count: 16_385), accepted: false, "16385 bytes")
        assertShape(.functionPrototype, "line1\nline2\r\n", accepted: true, "newlines are not a Core concern")
        assertShape(.functionPrototype, "not a signature at all", accepted: true, "Core never checks structure")
        assertShape(.functionPrototype, "a\0b", accepted: false, "NUL")
        XCTAssertThrowsError(try request(.functionPrototype, "a\0b").validateShape()) {
            XCTAssertEqual($0 as? VAVerificationError, .invalidRequest("invalid function prototype"))
        }
    }

    // MARK: (b) name and comment unchanged

    func testNameAndCommentShapeAreUnchanged() {
        assertShape(.functionName, nil, accepted: true, "nil")
        assertShape(.functionName, String(repeating: "n", count: 1024), accepted: true, "name 1024")
        assertShape(.functionName, String(repeating: "n", count: 1025), accepted: false, "name 1025")
        assertShape(.functionName, "  ", accepted: false, "blank name")
        assertShape(.functionName, "a\nb", accepted: false, "name LF")
        assertShape(.functionName, "a\rb", accepted: false, "name CR")
        assertShape(.functionName, "a\0b", accepted: false, "name NUL")
        assertShape(.functionComment, nil, accepted: true, "comment nil")
        assertShape(.functionComment, "line1\nline2\r\n  ", accepted: true, "comment may hold newlines and blanks")
        assertShape(.functionComment, "", accepted: true, "empty comment")
        assertShape(.functionComment, String(repeating: "c", count: 65_536), accepted: true, "comment 65536")
        assertShape(.functionComment, String(repeating: "c", count: 65_537), accepted: false, "comment 65537")
        assertShape(.functionComment, "a\0b", accepted: false, "comment NUL")
        XCTAssertThrowsError(try request(.functionName, "a\nb").validateShape()) {
            XCTAssertEqual($0 as? VAVerificationError, .invalidRequest("invalid function name"))
        }
        XCTAssertThrowsError(try request(.functionComment, "a\0b").validateShape()) {
            XCTAssertEqual($0 as? VAVerificationError, .invalidRequest("invalid function comment"))
        }
        XCTAssertThrowsError(try request(.functionComment, String(repeating: "c", count: 65_537)).validateShape()) {
            XCTAssertEqual($0 as? VAVerificationError, .budgetExceeded("request"))
        }
    }

    // MARK: (c) portable paths refuse the new kinds

    func testPortableVerifierRefusesBothNewKinds() {
        for kind in [VAEditKind.addressType, .functionPrototype] {
            let before = projection()
            let edit = VAEditIntent(target: target, kind: kind, value: "T", evidenceIDs: [UUID()])
            XCTAssertThrowsError(try VACandidateVerifier.verify(before: before, candidate: before, edits: [edit]),
                                 "\(kind)") {
                XCTAssertEqual($0 as? VAVerificationError, .unsupportedMutation)
            }
        }
    }

    func testReceiptHistoryRefusesBothNewKinds() throws {
        for kind in [VAEditKind.addressType, .functionPrototype] {
            let current = projection(revision: 1)
            let after = try current.stamp()
            let mutation = request(kind, "T")
            let receipt = try VAVerificationReceipt(
                request: mutation, decision: .accepted, before: stamp(0), after: after,
                mechanical: .candidateReadbackVerified, persistence: .pendingFreshProcessCheckpoint)
            let state = VAVerificationState(projection: current, receipts: [receipt])
            XCTAssertThrowsError(try VAAcceptedReceiptHistory(state: state), "\(kind)") {
                XCTAssertEqual($0 as? VAVerificationError, .unsupportedMutation)
            }
        }
    }

    // MARK: (d) eligibility

    private func evidence(_ query: VAQueryKind, at s: VAProjectionStamp) -> VAEvidenceRecord {
        VAEvidenceRecord(id: UUID(), observation: VANativeObservation(
            stamp: s, target: target, query: query, completeness: .complete, content: "observed"),
            capturedAt: Date(timeIntervalSince1970: 1))
    }

    func testEligibilityIsKindAware() {
        let s = stamp(3)
        func check(_ query: VAQueryKind, _ kind: VAEditKind) throws {
            try VAEvidenceEligibility.requireMutationEvidence(evidence(query, at: s), for: target, kind: kind, at: s)
        }
        XCTAssertThrowsError(try check(.disassembly, .addressType)) {
            XCTAssertEqual($0 as? VAVerificationError, .incompleteEvidence)
        }
        XCTAssertThrowsError(try check(.functionFacts, .addressType))
        XCTAssertNoThrow(try check(.addressFacts, .addressType))
        for kind in [VAEditKind.functionName, .functionComment, .functionPrototype] {
            XCTAssertThrowsError(try check(.addressFacts, kind), "\(kind)") {
                XCTAssertEqual($0 as? VAVerificationError, .incompleteEvidence)
            }
            XCTAssertNoThrow(try check(.disassembly, kind))
            XCTAssertNoThrow(try check(.functionFacts, kind))
            XCTAssertThrowsError(try check(.annotations, kind))
        }
        // The kind-agnostic signature keeps today's behavior.
        XCTAssertNoThrow(try VAEvidenceEligibility.requireMutationEvidence(evidence(.disassembly, at: s), for: target, at: s))
        XCTAssertThrowsError(try VAEvidenceEligibility.requireMutationEvidence(evidence(.addressFacts, at: s), for: target, at: s))
        // Stamp and target checks still apply to the new kind.
        XCTAssertThrowsError(try VAEvidenceEligibility.requireMutationEvidence(
            evidence(.addressFacts, at: stamp(2)), for: target, kind: .addressType, at: s)) {
            XCTAssertEqual($0 as? VAVerificationError, .mismatchedEvidence)
        }
    }

    // MARK: Field class mapping

    func testFieldClassMapping() {
        XCTAssertEqual(VerifiedFieldClass.allCases.count, 4)
        for fieldClass in VerifiedFieldClass.allCases {
            XCTAssertEqual(VerifiedFieldClass(editKind: fieldClass.editKind), fieldClass)
        }
        XCTAssertEqual(VerifiedFieldClass(.name), .name)
        XCTAssertEqual(VerifiedFieldClass(.comment), .comment)
        XCTAssertEqual(VerifiedFieldClass.name.annotationField, .name)
        XCTAssertEqual(VerifiedFieldClass.comment.annotationField, .comment)
        XCTAssertNil(VerifiedFieldClass.addressType.annotationField)
        XCTAssertNil(VerifiedFieldClass.functionSignature.annotationField)
        XCTAssertEqual(VerifiedFieldClass.addressType.editKind, .addressType)
        XCTAssertEqual(VerifiedFieldClass.functionSignature.editKind, .functionPrototype)
        XCTAssertEqual(VerifiedFieldClass.functionSignature.rawValue, "functionSignature")
    }

    // MARK: (e) type-name codec

    func testTypeNameCodecTrimsAndBounds() throws {
        XCTAssertEqual(try VerifiedFieldCodec.canonicalTypeName("  struct Foo \n"), "struct Foo")
        XCTAssertEqual(try VerifiedFieldCodec.canonicalTypeName("\tT\t"), "T")
        // Identical to the store's trim for every accepted input.
        for text in [" a ", "\nb\n", "c d", "  e\t"] {
            XCTAssertEqual(try VerifiedFieldCodec.canonicalTypeName(text), text.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        XCTAssertThrowsError(try VerifiedFieldCodec.canonicalTypeName("")) {
            XCTAssertEqual($0 as? VerifiedFieldCodecError, .emptyTypeName)
        }
        XCTAssertThrowsError(try VerifiedFieldCodec.canonicalTypeName(" \n\t ")) {
            XCTAssertEqual($0 as? VerifiedFieldCodecError, .emptyTypeName)
        }
        XCTAssertEqual(try VerifiedFieldCodec.canonicalTypeName(String(repeating: "a", count: 256)).utf8.count, 256)
        // The bound applies after trimming.
        XCTAssertEqual(try VerifiedFieldCodec.canonicalTypeName(" " + String(repeating: "a", count: 256) + " ").utf8.count, 256)
        XCTAssertThrowsError(try VerifiedFieldCodec.canonicalTypeName(String(repeating: "a", count: 257))) {
            XCTAssertEqual($0 as? VerifiedFieldCodecError, .typeNameTooLong)
        }
        XCTAssertThrowsError(try VerifiedFieldCodec.canonicalTypeName(String(repeating: "é", count: 129))) {
            XCTAssertEqual($0 as? VerifiedFieldCodecError, .typeNameTooLong)
        }
        for bad in ["a\nb", "a\rb", "a\0b"] {
            XCTAssertThrowsError(try VerifiedFieldCodec.canonicalTypeName(bad)) {
                XCTAssertEqual($0 as? VerifiedFieldCodecError, .typeNameInvalidCharacter)
            }
        }
        // Whatever the codec accepts, Core validation accepts.
        let canonical = (try? VerifiedFieldCodec.canonicalTypeName("  Foo  ")) ?? ""
        XCTAssertNoThrow(try request(.addressType, canonical).validateShape())
    }

    // MARK: (f) signature codec

    private func rows(_ pairs: [(String, String)]) -> [ArgOverride] {
        pairs.map { ArgOverride(rowToken: UUID().uuidString.lowercased(), name: $0.0, type: $0.1, provenance: .script) }
    }

    func testSignatureRoundTripsEachTriState() throws {
        var samples: [FunctionSignatureOverride] = [
            FunctionSignatureOverride(),
            FunctionSignatureOverride(returnType: "int"),
            FunctionSignatureOverride(returnType: ""),
            FunctionSignatureOverride(parameterList: .authoritative([])),
            FunctionSignatureOverride(returnType: "void *", parameterList: .authoritative(rows([("a", "int"), ("b", "char *")])),
                                      variadicState: .variadic, noReturnState: .noReturn),
            FunctionSignatureOverride(parameterList: .authoritative(rows([("x", "long")])), variadicState: .fixed,
                                      noReturnState: .returns),
        ]
        for variadic in [FunctionSignatureOverride.VariadicState.unspecified, .fixed, .variadic] {
            for noReturn in FunctionSignatureOverride.NoReturnState.allCases {
                samples.append(FunctionSignatureOverride(variadicState: variadic, noReturnState: noReturn))
            }
        }
        samples.append(FunctionSignatureOverride(quarantinedLegacyArgs: [
            LegacyArgOverride(originalIndex: 3, originalOrder: 0, name: "q", type: "int"),
            LegacyArgOverride(originalIndex: 1, originalOrder: 1, name: "r", type: "char")]))
        var seen = Set<String>()
        for sample in samples {
            let text = try VerifiedFieldCodec.canonicalSignature(sample)
            seen.insert(text)
            let back = try VerifiedFieldCodec.decodeSignature(text)
            XCTAssertEqual(back.returnType, sample.returnType)
            XCTAssertEqual(back.variadicState, sample.variadicState)
            XCTAssertEqual(back.noReturnState, sample.noReturnState)
            XCTAssertEqual(back.quarantinedLegacyArgs, sample.quarantinedLegacyArgs)
            switch (back.parameterList, sample.parameterList) {
            case (.unspecified, .unspecified): break
            case (.authoritative(let x), .authoritative(let y)):
                XCTAssertEqual(x.map(\.name), y.map(\.name)); XCTAssertEqual(x.map(\.type), y.map(\.type))
            default: XCTFail("parameter-list state changed: \(text)")
            }
            XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(back), text)
        }
        // Unspecified and explicit (void) are distinct, as are nil and empty return types.
        XCTAssertNotEqual(try VerifiedFieldCodec.canonicalSignature(FunctionSignatureOverride()),
                          try VerifiedFieldCodec.canonicalSignature(FunctionSignatureOverride(parameterList: .authoritative([]))))
        XCTAssertNotEqual(try VerifiedFieldCodec.canonicalSignature(FunctionSignatureOverride(returnType: "")),
                          try VerifiedFieldCodec.canonicalSignature(FunctionSignatureOverride()))
        XCTAssertGreaterThanOrEqual(seen.count, 15, "distinct states have distinct canonical bytes")
    }

    func testSignatureIgnoresRowTokenAndProvenance() throws {
        func make(_ token: String, _ provenance: ArgOverride.Provenance) -> FunctionSignatureOverride {
            FunctionSignatureOverride(returnType: "int", parameterList: .authoritative([
                ArgOverride(rowToken: token + "1", name: "a", type: "int", provenance: provenance),
                ArgOverride(rowToken: token + "2", name: "b", type: "char", provenance: provenance)]),
                variadicState: .fixed, noReturnState: .unspecified)
        }
        let base = try VerifiedFieldCodec.canonicalSignature(make("t-", .user))
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(make("other-", .user)), base)
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(make("t-", .debug)), base)
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(make("zzz-", .legacy)), base)
        XCTAssertFalse(base.contains("rowToken"))
        XCTAssertFalse(base.contains("provenance"))
        // Order is content: swapping rows changes the bytes.
        let swapped = FunctionSignatureOverride(returnType: "int", parameterList: .authoritative(rows([("b", "char"), ("a", "int")])),
                                                variadicState: .fixed)
        XCTAssertNotEqual(try VerifiedFieldCodec.canonicalSignature(swapped), base)
        // Keys are sorted.
        XCTAssertTrue(base.hasPrefix("{\"codec\":1,\"noReturnState\""), base)
    }

    func testSignatureBoundsRefuseAtTheEdge() throws {
        func sig(params: Int = 0, name: Int = 1, type: Int = 1, returnType: String? = nil) -> FunctionSignatureOverride {
            FunctionSignatureOverride(returnType: returnType, parameterList: .authoritative((0..<params).map { _ in
                ArgOverride(name: String(repeating: "n", count: name), type: String(repeating: "t", count: type))
            }))
        }
        func code(_ value: FunctionSignatureOverride) -> VerifiedFieldCodecError? {
            do { _ = try VerifiedFieldCodec.canonicalSignature(value); return nil }
            catch { return error as? VerifiedFieldCodecError }
        }
        XCTAssertNil(code(sig(params: 64)))
        XCTAssertEqual(code(sig(params: 65)), .tooManyParameters)
        XCTAssertNil(code(sig(params: 1, name: 256)))
        XCTAssertEqual(code(sig(params: 1, name: 257)), .parameterNameTooLong)
        XCTAssertNil(code(sig(params: 1, type: 512)))
        XCTAssertEqual(code(sig(params: 1, type: 513)), .parameterTypeTooLong)
        XCTAssertNil(code(sig(returnType: String(repeating: "r", count: 512))))
        XCTAssertEqual(code(sig(returnType: String(repeating: "r", count: 513))), .returnTypeTooLong)
        XCTAssertEqual(code(FunctionSignatureOverride(returnType: "a\0b")), .signatureInvalidCharacter)
        XCTAssertEqual(code(FunctionSignatureOverride(parameterList: .authoritative(rows([("a\0", "int")])))), .signatureInvalidCharacter)
        // 64 parameters of 256 + 512 bytes exceed 16 KiB in total.
        XCTAssertEqual(code(sig(params: 64, name: 256, type: 512)), .signatureTooLarge)
        // Total-size edge: grow the parameter types until the canonical form is exactly 16384 bytes.
        let overhead = try VerifiedFieldCodec.canonicalSignature(sig(params: 64, name: 100, type: 100)).utf8.count
        let room = VerifiedFieldCodec.maximumSignatureBytes - overhead
        // Spend the room across 64 types of at most 512 bytes (one extra byte per type, up to the type bound).
        let perType = 100 + room / 64
        XCTAssertLessThanOrEqual(perType + 1, 512, "fixture must stay inside the per-field bounds")
        let extra = room % 64
        let edge = FunctionSignatureOverride(parameterList: .authoritative((0..<64).map {
            ArgOverride(name: String(repeating: "n", count: 100),
                        type: String(repeating: "t", count: 100 + room / 64 + ($0 < extra ? 1 : 0)))
        }), variadicState: .unspecified, noReturnState: .unspecified)
        let exact = try VerifiedFieldCodec.canonicalSignature(edge)
        XCTAssertEqual(exact.utf8.count, VerifiedFieldCodec.maximumSignatureBytes)
        XCTAssertEqual(try VerifiedFieldCodec.decodeSignature(exact).args.count, 64)
        let over = FunctionSignatureOverride(returnType: "r", parameterList: edge.parameterList)
        XCTAssertEqual(code(over), .signatureTooLarge)
    }

    func testSignatureDecoderRefusesMalformedAndNonCanonicalInput() throws {
        let good = try VerifiedFieldCodec.canonicalSignature(
            FunctionSignatureOverride(returnType: "int", parameterList: .authoritative(rows([("a", "int")]))))
        func code(_ text: String) -> VerifiedFieldCodecError? {
            do { _ = try VerifiedFieldCodec.decodeSignature(text); return nil }
            catch { return error as? VerifiedFieldCodecError }
        }
        XCTAssertNil(code(good))
        XCTAssertEqual(code("not json"), .malformedSignature)
        XCTAssertEqual(code("{}"), .malformedSignature)
        XCTAssertEqual(code(good.replacingOccurrences(of: "\"codec\":1", with: "\"codec\":2")), .malformedSignature)
        XCTAssertEqual(code(good.replacingOccurrences(of: "{", with: "{ ", options: [], range: good.startIndex..<good.index(after: good.startIndex))),
                       .nonCanonicalSignature)
        XCTAssertEqual(code(String(good.dropLast()) + ",\"rowToken\":\"x\"}"), .nonCanonicalSignature)
        XCTAssertEqual(code(good + String(repeating: " ", count: 16_384)), .signatureTooLarge)
    }

    // MARK: (g) audit mapping refuses the new kinds

    private func acceptedReceipt(_ kind: VAEditKind, _ value: String?, evidenceID: UUID) throws -> VAVerificationReceipt {
        let mutation = VAMutationRequest(
            base: stamp(0),
            edits: [VAEditIntent(target: target, kind: kind, value: value, evidenceIDs: [evidenceID])],
            rationale: "S1 mapping test")
        return try VAVerificationReceipt(
            request: mutation, decision: .accepted, before: stamp(0), after: stamp(1),
            mechanical: .candidateReadbackVerified, persistence: .pendingFreshProcessCheckpoint,
            recordedAt: Date(timeIntervalSince1970: 1234.5))
    }

    func testAuditMappingRefusesNewKindsAndStillMapsNameAndComment() throws {
        for (kind, value) in [(VAEditKind.addressType, "T"), (.functionPrototype, "int f(void)")] {
            let evidenceID = UUID()
            let receipt = try acceptedReceipt(kind, value, evidenceID: evidenceID)
            let links = [VerifiedAnnotationEvidenceLink(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))]
            XCTAssertThrowsError(try VerifiedAnnotationAuditRecord(receipt: receipt, nativeEvidenceLinks: links), "\(kind)") {
                XCTAssertEqual($0 as? VerifiedAnnotationAuditMappingError, .unsupportedEditKind(kind))
            }
            XCTAssertThrowsError(try VerifiedAnnotationAuditRecord.auditValueLimit(for: kind))
        }
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .functionName), 256)
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .functionComment), 2048)
        for (kind, value) in [(VAEditKind.functionName, "named"), (.functionComment, "commented")] {
            let evidenceID = UUID()
            let receipt = try acceptedReceipt(kind, value, evidenceID: evidenceID)
            let links = [VerifiedAnnotationEvidenceLink(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))]
            XCTAssertNoThrow(try VerifiedAnnotationAuditRecord(receipt: receipt, nativeEvidenceLinks: links), "\(kind)")
        }
    }

    // MARK: (h) golden stamp (ruling 3, T4)

    // Computed before any change on this tree (base 2bed4c34f). The bytes hashed are the
    // NativeAnnotationProjector body: sorted-key canonical JSON (slashes unescaped) of
    // {domain: "com.jeff.macscope.verified-annotation-projection.v1", entries: [(slot, address, name, comment)]},
    // entries ordered by (slot, address), nil fields omitted, then SHA-256 hex. A standalone swiftc script
    // that mirrors Entry/Body and the VACanonicalJSON encoder settings produced these values, and this test
    // checks them against the production type. S3 must keep both passing without editing them.
    func testGoldenNameCommentStampsAreUnchanged() {
        let sibling = ImageSlot(rawValue: 1)
        let first: [ImageAddress: AddressOverride] = [
            .primary(0x1000): AddressOverride(customName: "alpha", customComment: "first comment"),
            .primary(0x2000): AddressOverride(customName: "beta"),
            ImageAddress(slot: sibling, address: 0x1000): AddressOverride(customComment: "sibling note"),
            .primary(0x3000): AddressOverride(tag: "ignored: no name or comment"),
        ]
        XCTAssertEqual(NativeAnnotationProjector.digest(first),
                       "1b8c2c91648f746515c861e81f8875a4d0322e2f126ac34b0bcec35186f6ce84")
        let second: [ImageAddress: AddressOverride] = [
            .primary(0x40): AddressOverride(customName: "ns/entry \"main\" é", customComment: "line one\nline two"),
            ImageAddress(slot: ImageSlot(rawValue: 2), address: 0xFFFF_FFFF_0000): AddressOverride(customComment: "tail"),
            .primary(0x10): AddressOverride(customName: "only-name"),
        ]
        XCTAssertEqual(NativeAnnotationProjector.digest(second),
                       "9e3f6adf083d2264f7da169fac7f1eca1442ca9b13294186611b1f88a49d4e33")
    }
}
