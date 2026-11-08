#if DEBUG
import Foundation
import XCTest
@testable import MacScope

/// Authored, unrun. Synthetic data only; no app or binary acceptance is asserted.
final class CalleeClaimEnvelopeTests: XCTestCase {
    private func ledger() throws -> CalleeClaimLedger {
        let inventory = VACalleeInventory(function: VAAddress64(0x1000), callees: [],
            inventoryDigest: String(repeating: "a", count: 64))
        let binding = VACalleeClaimBinding(imageOwner: UUID(), slot: 0, function: inventory.function,
            analysisGeneration: UUID(), inventoryDigest: inventory.inventoryDigest)
        var result = CalleeClaimLedger()
        try result.open(claimID: UUID(), inventory: inventory, binding: binding, atMilliseconds: 1)
        return result
    }
    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: VerifiedAnnotationAuditCodec.encode(value)) as? [String: Any])
    }
    private func bytes(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func manifest(_ envelope: CalleeClaimEnvelope?, features: [String]) -> WorkspacePackageManifest {
        WorkspacePackageManifest(formatVersion: 1, documentID: UUID(), workspaceUUID: UUID(),
            workspaceName: "Claim fixture", createdAt: Date(timeIntervalSince1970: 1),
            modifiedAt: Date(timeIntervalSince1970: 1), binaries: [], session: nil,
            requiredReaderFeatures: features, calleeClaims: envelope)
    }
    private func read(_ value: WorkspacePackageManifest, features: Set<String>? = nil) throws {
        _ = try MacScopeDocumentPackage.decodedManifestForReaderTesting(
            MacScopeDocumentPackage.encodedManifest(value),
            supportedFeatures: features ?? MacScopeDocumentPackage.supportedReaderFeatures)
    }
    func testEnvelopeRoundTripRestoresClaimsAndBindings() throws {
        let original = try ledger()
        let envelope = try CalleeClaimEnvelope(ledger: original)
        let decoded = try JSONDecoder().decode(CalleeClaimEnvelope.self,
            from: VerifiedAnnotationAuditCodec.encode(envelope))
        XCTAssertEqual(try decoded.makeLedger(), original)
    }
    func testEnvelopeRejectsDuplicateClaimIDs() throws {
        let first = try XCTUnwrap(ledger().events.first)
        let duplicate = VACalleeClaimEvent(sequence: 2, atMilliseconds: 2, claimID: first.claimID,
            kind: .claimOpened, revision: 1, binding: first.binding, inventory: first.inventory)
        XCTAssertThrowsError(try CalleeClaimEnvelope(events: [.init(first), .init(duplicate)])) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .duplicateClaimID(first.claimID))
        }
    }
    func testEnvelopeRejectsDigestMismatch() throws {
        var value = try object(CalleeClaimEnvelope(ledger: ledger()))
        var events = try XCTUnwrap(value["events"] as? [[String: Any]])
        events[0]["digest"] = String(repeating: "0", count: 64)
        value["events"] = events
        XCTAssertThrowsError(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(value))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .digestMismatch)
        }
    }
    func testEnvelopeRejectsUnknownKeysAndWrongSchema() throws {
        var value = try object(CalleeClaimEnvelope.empty)
        value["unexpected"] = true
        XCTAssertThrowsError(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(value)))
        value.removeValue(forKey: "unexpected")
        value["schemaVersion"] = 2
        XCTAssertThrowsError(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(value))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .unsupportedSchema(2))
        }
    }
    func testEnvelopeRejectsUnknownEventWrapperKeys() throws {
        var value = try object(CalleeClaimEnvelope(ledger: ledger()))
        var events = try XCTUnwrap(value["events"] as? [[String: Any]])
        events[0]["unexpected"] = true
        value["events"] = events
        XCTAssertThrowsError(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(value)))
    }
    func testEnvelopeRejectsTooManyEventsBeforeReplay() throws {
        let event = try CalleeClaimEnvelope.Event(XCTUnwrap(ledger().events.first))
        XCTAssertThrowsError(try CalleeClaimEnvelope(events: Array(repeating: event, count: 16_385))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .tooManyEvents)
        }
    }
    func testEnvelopeRejectsTooManyClaims() throws {
        let first = try XCTUnwrap(ledger().events.first)
        let events = try (1...257).map { sequence in
            try CalleeClaimEnvelope.Event(VACalleeClaimEvent(sequence: UInt64(sequence), atMilliseconds: 1,
                claimID: UUID(), kind: .claimOpened, revision: 1, binding: first.binding, inventory: first.inventory))
        }
        XCTAssertThrowsError(try CalleeClaimEnvelope(events: events)) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .tooManyClaims)
        }
    }
    func testEnvelopeRejectsOversizedEventWithoutTruncating() throws {
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes:
            Data(repeating: 32, count: CalleeClaimEnvelope.maximumEventBytes + 1))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .eventTooLarge)
        }
    }
    func testEnvelopeRejectsUnknownEventKeysAndTooManyCallees() throws {
        let event = try XCTUnwrap(ledger().events.first)
        var value = try object(event)
        value["unexpected"] = true
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes: bytes(value)))
        value.removeValue(forKey: "unexpected")
        var inventory = try XCTUnwrap(value["inventory"] as? [String: Any])
        inventory["callees"] = Array(repeating: [String: String](), count: 8_193)
        value["inventory"] = inventory
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes: bytes(value))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .tooManyCallees)
        }
    }

    func testClaimFeatureRequiredBothDirections() throws {
        let envelope = try CalleeClaimEnvelope(ledger: ledger())
        XCTAssertThrowsError(try read(manifest(envelope, features: []))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .featureMissing)
        }
        XCTAssertThrowsError(try read(manifest(nil, features: [WorkspacePackageManifest.calleeClaimsReaderFeature]))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .featureWithoutClaims)
        }
    }
    func testOldReaderRefusesManifestFeatureBeforeEnvelopeDecode() throws {
        let envelope = try CalleeClaimEnvelope(ledger: ledger())
        let old = MacScopeDocumentPackage.supportedReaderFeatures.subtracting([WorkspacePackageManifest.calleeClaimsReaderFeature])
        XCTAssertThrowsError(try read(manifest(envelope, features: [WorkspacePackageManifest.calleeClaimsReaderFeature]), features: old)) {
            XCTAssertEqual($0 as? MacScopeDocumentPackage.UnsupportedReaderFeaturesError,
                .init(features: [WorkspacePackageManifest.calleeClaimsReaderFeature]))
        }
    }
    func testEmptyEnvelopePreservesDefaultManifestBytes() throws {
        var value = manifest(nil, features: [])
        let oldShape = try VerifiedAnnotationAuditCodec.encode(value)
        value.calleeClaims = .empty
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(value), oldShape)
        XCTAssertFalse(try object(value).keys.contains("calleeClaims"))
        XCTAssertFalse(try object(value).keys.contains("requiredReaderFeatures"))
    }
    /// Literal byte golden: the structural test above compares decoded fields, so a change in key
    /// order, whitespace or date/number format would pass it. This pins every byte of the encoding
    /// of a manifest with no callee claims (nil and explicit-empty envelopes, no feature declared).
    func testNoClaimsManifestEncodesToExactLiteralBytes() throws {
        let expected = [
            "{",
            "  \"binaries\" : [",
            "",
            "  ],",
            "  \"bookmarkResolutionDecision\" : \"resolve_stored_bookmarks\",",
            "  \"createdAt\" : \"1970-01-01T00:00:01.000Z\",",
            "  \"documentID\" : \"00000000-0000-0000-0000-0000000000D1\",",
            "  \"formatIdentifier\" : \"com.jeff.macscope.workspace-package\",",
            "  \"formatVersion\" : 1,",
            "  \"inputCopyingDecision\" : \"copy_inputs_into_package\",",
            "  \"modifiedAt\" : \"1970-01-01T00:00:01.000Z\",",
            "  \"workspaceName\" : \"Claim fixture\",",
            "  \"workspaceUUID\" : \"00000000-0000-0000-0000-0000000000A1\"",
            "}",
        ].joined(separator: "\n")
        var value = manifest(nil, features: [])
        value.documentID = try XCTUnwrap(UUID(uuidString: "00000000-0000-0000-0000-0000000000D1"))
        value.workspaceUUID = try XCTUnwrap(UUID(uuidString: "00000000-0000-0000-0000-0000000000A1"))
        let nilBytes = try MacScopeDocumentPackage.encodedManifest(value)
        XCTAssertEqual(String(decoding: nilBytes, as: UTF8.self), expected)
        XCTAssertEqual(Array(nilBytes), Array(expected.utf8))
        value.calleeClaims = .empty
        XCTAssertEqual(Array(try MacScopeDocumentPackage.encodedManifest(value)), Array(expected.utf8))
    }
    func testEnvelopeRejectsSkippedRevisionBeforePublication() throws {
        let first = try XCTUnwrap(ledger().events.first)
        let invalid = VACalleeClaimEvent(sequence: 2, atMilliseconds: 2, claimID: first.claimID,
            kind: .claimSuperseded, revision: 3, binding: first.binding, inventory: first.inventory)
        XCTAssertThrowsError(try CalleeClaimEnvelope(events: [.init(first), .init(invalid)])) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .invalidLedger)
        }
    }
    func testEnvelopeRejectsDuplicateClaimIDMembersBeforeFoundationDecode() throws {
        let event = try CalleeClaimEnvelope.Event(XCTUnwrap(ledger().events.first))
        let suffix = String(decoding: event.canonicalBytes, as: UTF8.self).dropFirst()
        let duplicate = "{\"claimID\":\"\(UUID().uuidString)\"," + String(suffix)
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes: Data(duplicate.utf8))) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent)
        }
    }
    /// Store boundary: the production refusal is CalleeClaimEnvelope.Event.makeEvent() (decode, sorted
    /// re-encode, byte compare). Since CC-ADMIT the package type refuses the tampered bytes before an
    /// Event exists, so no Event, envelope or ledger can carry them to makeEvent()/makeLedger().
    func testOpaqueProjectionUnknownKeyRejectsAtStoreBoundary() throws {
        let first = try XCTUnwrap(ledger().events.first)
        let old = try XCTUnwrap(first.binding)
        let epoch = VAProjectionStamp(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
            revision: 1, digest: String(repeating: "b", count: 64))
        let binding = VACalleeClaimBinding(imageOwner: old.imageOwner, slot: old.slot, function: old.function,
            analysisGeneration: old.analysisGeneration, projectionEpoch: epoch, inventoryDigest: old.inventoryDigest)
        let event = VACalleeClaimEvent(sequence: 1, atMilliseconds: 1, claimID: first.claimID,
            kind: .claimOpened, revision: 1, binding: binding, inventory: first.inventory)
        var value = try object(event)
        var bound = try XCTUnwrap(value["binding"] as? [String: Any])
        var projection = try XCTUnwrap(bound["projectionEpoch"] as? [String: Any])
        projection["unexpected"] = true
        bound["projectionEpoch"] = projection
        value["binding"] = bound
        let tampered = try bytes(value)
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes: tampered),
                             "store boundary: Event(canonicalBytes:) must refuse unknown projectionEpoch key") {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent, "store boundary error kind")
        }
        // Untampered bytes still reach makeEvent() and succeed, so the refusal above is the key, not the path.
        let clean = try CalleeClaimEnvelope.Event(canonicalBytes: bytes(object(event)))
        XCTAssertNoThrow(try clean.makeEvent(), "store boundary: clean stamped event passes makeEvent()")
    }
    // CC-ADMIT: package-boundary admission of binding.projectionEpoch (no Store, no makeLedger).
    private func stampedEventObject(_ stamp: VAProjectionStamp?) throws -> [String: Any] {
        let first = try XCTUnwrap(ledger().events.first)
        let old = try XCTUnwrap(first.binding)
        let binding = VACalleeClaimBinding(imageOwner: old.imageOwner, slot: old.slot, function: old.function,
            analysisGeneration: old.analysisGeneration, projectionEpoch: stamp, inventoryDigest: old.inventoryDigest)
        return try object(VACalleeClaimEvent(sequence: 1, atMilliseconds: 1, claimID: first.claimID,
            kind: .claimOpened, revision: 1, binding: binding, inventory: first.inventory))
    }
    private func realStamp() -> VAProjectionStamp {
        VAProjectionStamp(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
            revision: 1, digest: String(repeating: "b", count: 64))
    }
    private func withEpoch(_ event: [String: Any], _ edit: (inout [String: Any]) -> Void) throws -> Data {
        var value = event
        var bound = try XCTUnwrap(value["binding"] as? [String: Any])
        var epoch = try XCTUnwrap(bound["projectionEpoch"] as? [String: Any])
        edit(&epoch)
        bound["projectionEpoch"] = epoch
        value["binding"] = bound
        return try bytes(value)
    }
    private func wire(_ data: Data) -> [String: Any] {
        ["schemaVersion": 1, "events": [["canonicalBytes": data.base64EncodedString(),
            "digest": VerifiedAnnotationAuditCodec.sha256Hex(data)]]]
    }
    /// Package-canonical manifest bytes (encodedManifest) carrying `data` as the single claim event:
    /// the clean event's base64 and digest are replaced textually so every other byte stays canonical.
    private func manifestBytes(carrying data: Data) throws -> Data {
        let clean = try CalleeClaimEnvelope(ledger: ledger())
        let event = try XCTUnwrap(clean.events.first)
        var text = String(decoding: try MacScopeDocumentPackage.encodedManifest(
            manifest(clean, features: [WorkspacePackageManifest.calleeClaimsReaderFeature])), as: UTF8.self)
        func escaped(_ value: String) -> String { value.replacingOccurrences(of: "/", with: "\\/") }
        let oldBase64 = escaped(event.canonicalBytes.base64EncodedString())
        XCTAssertTrue(text.contains(oldBase64), "stage d setup: clean event base64 present in encoded manifest")
        text = text.replacingOccurrences(of: oldBase64, with: escaped(data.base64EncodedString()))
        text = text.replacingOccurrences(of: event.digest, with: VerifiedAnnotationAuditCodec.sha256Hex(data))
        return Data(text.utf8)
    }
    private func validate(manifestData: Data) throws {
        _ = try MacScopeDocumentPackage.validatedContents(manifestData: manifestData, attachmentsByBinaryID: [:])
    }
    private func assertMalformed(_ data: Data, _ label: String, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes: data),
                             "stage a Event(canonicalBytes:): \(label)", file: file, line: line) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent, "stage a error kind: \(label)", file: file, line: line)
        }
        XCTAssertThrowsError(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(wire(data))),
                             "stage c wire decode: \(label)", file: file, line: line) {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent, "stage c error kind: \(label)", file: file, line: line)
        }
    }
    func testOpaqueProjectionUnknownKeyRejectsAtPackageAdmission() throws {
        let data = try withEpoch(stampedEventObject(realStamp())) { $0["unexpected"] = true }
        XCTAssertThrowsError(try CalleeClaimEnvelope.Event(canonicalBytes: data),
                             "stage a Event(canonicalBytes:) must reject unknown projectionEpoch key") {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent, "stage a error kind")
        }
        XCTAssertThrowsError(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(wire(data))),
                             "stage c wire decode must reject unknown projectionEpoch key") {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent, "stage c error kind")
        }
        let manifestData = try manifestBytes(carrying: data)
        XCTAssertThrowsError(try validate(manifestData: manifestData),
                             "stage d validatedContents must reject unknown projectionEpoch key") {
            XCTAssertEqual($0 as? CalleeClaimEnvelopeError, .malformedEvent, "stage d error kind (unwrapped)")
        }
    }
    func testProducedProjectionStampAndOmittedStampAreAdmitted() throws {
        for stamp in [Optional(realStamp()), nil] {
            let label = stamp == nil ? "omitted stamp" : "produced stamp"
            let data = try bytes(stampedEventObject(stamp))
            var event: CalleeClaimEnvelope.Event?
            XCTAssertNoThrow(event = try CalleeClaimEnvelope.Event(canonicalBytes: data), "stage a: \(label)")
            XCTAssertNoThrow(try CalleeClaimEnvelope(events: [XCTUnwrap(event, "stage b event: \(label)")]), "stage b envelope(events:): \(label)")
            XCTAssertNoThrow(try JSONDecoder().decode(CalleeClaimEnvelope.self, from: bytes(wire(data))), "stage c wire decode: \(label)")
            XCTAssertNoThrow(try validate(manifestData: manifestBytes(carrying: data)), "stage d validatedContents: \(label)")
            let rebuilt = try CalleeClaimEnvelope(events: [XCTUnwrap(event)]).makeLedger()
            XCTAssertEqual(rebuilt.events.count, 1, "makeLedger event count: \(label)")
            XCTAssertEqual(try CalleeClaimEnvelope(ledger: rebuilt).events.first?.canonicalBytes, data,
                           "makeLedger byte-identical re-encode: \(label)")
        }
    }
    func testMalformedProjectionStampVariantsRejectAtPackageAdmission() throws {
        let event = try stampedEventObject(realStamp())
        var variants: [(String, Data)] = []
        for key in ["workspaceID", "documentID", "installationID", "revision", "digest"] {
            variants.append(("missing \(key)", try withEpoch(event) { $0[key] = nil }))
        }
        variants.append(("digest 63 hex", try withEpoch(event) { $0["digest"] = String(repeating: "b", count: 63) }))
        variants.append(("digest uppercase hex", try withEpoch(event) { $0["digest"] = String(repeating: "B", count: 64) }))
        // The real encoder emits uppercase UUID spelling, so the lowercase spelling is non-canonical.
        let lowered = try withEpoch(event) {
            $0["workspaceID"] = ($0["workspaceID"] as? String)?.lowercased() }
        variants.append(("lowercase UUID", lowered))
        variants.append(("revision as string", try withEpoch(event) { $0["revision"] = "1" }))
        var nulled = event
        var bound = try XCTUnwrap(nulled["binding"] as? [String: Any])
        bound["projectionEpoch"] = NSNull()
        nulled["binding"] = bound
        variants.append(("projectionEpoch null", try bytes(nulled)))
        let original = try withEpoch(event) { _ in }
        XCTAssertNotEqual(lowered, original, "guard: lowercase variant differs from real encoder output")
        for (label, data) in variants { try assertMalformed(data, label) }
    }
    func testProjectionMirrorKeysMatchCoreStamp() {
        let core = Mirror(reflecting: realStamp()).children.compactMap(\.label)
        let mirror = Mirror(reflecting: VerifiedAnnotationProjectionIdentity(workspaceID: UUID(),
            documentID: UUID(), installationID: UUID(), revision: 1, digest: "")).children.compactMap(\.label)
        XCTAssertEqual(Set(core), Set(mirror), "CC-ADMIT-4 label sets")
        XCTAssertEqual(core.count, mirror.count, "CC-ADMIT-4 label counts")
    }
    func testClaimFeatureCoexistsWithAuditAndTypedEdits() throws {
        let claims = try CalleeClaimEnvelope(ledger: ledger())
        let classes: [VerifiedAnnotationAuditFieldClass?] = [nil, .addressType]
        for fieldClass in classes {
            var value = manifest(claims, features: [WorkspacePackageManifest.calleeClaimsReaderFeature,
                WorkspacePackageManifest.verifiedAnnotationAuditReaderFeature])
            let before = VerifiedAnnotationProjectionIdentity(workspaceID: value.workspaceUUID,
                documentID: value.documentID, installationID: UUID(), revision: 1,
                digest: String(repeating: "a", count: 64))
            let record = try VerifiedAnnotationAuditRecord(operationID: UUID(),
                requestDigest: String(repeating: "b", count: 64), decision: .rejected, before: before,
                after: nil, mechanical: .notVerified, persistence: .notApplicable, failure: "synthetic refusal",
                recordedAtMilliseconds: 1, nativeEvidenceLinks: [], fieldClass: fieldClass)
            value.verifiedAnnotationAudit = try .empty.appending(record,
                workspaceID: value.workspaceUUID, documentID: value.documentID)
            if fieldClass != nil { value.requiredReaderFeatures.append(WorkspacePackageManifest.verifiedAnnotationTypedEditsReaderFeature) }
            XCTAssertNoThrow(try read(value))
            if fieldClass != nil {
                value.requiredReaderFeatures.removeAll { $0 == WorkspacePackageManifest.verifiedAnnotationTypedEditsReaderFeature }
                XCTAssertThrowsError(try read(value)) {
                    XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .typedEditsFeatureMissing)
                }
                value.requiredReaderFeatures.append(WorkspacePackageManifest.verifiedAnnotationTypedEditsReaderFeature)
            }
            value.calleeClaims = nil
            value.requiredReaderFeatures.removeAll { $0 == WorkspacePackageManifest.calleeClaimsReaderFeature }
            XCTAssertNoThrow(try read(value))
        }
    }
}
#endif
