import Foundation

/// Portable integrity/bounds errors. Semantic replay is performed by the Services mapping.
enum CalleeClaimEnvelopeError: Error, Equatable {
    case unsupportedSchema(Int)
    case malformedEnvelope
    case malformedEvent
    case eventTooLarge
    case envelopeTooLarge
    case tooManyEvents
    case tooManyClaims
    case tooManyCallees
    case duplicateClaimID(UUID)
    case digestMismatch
    case invalidLedger
    case featureMissing
    case featureWithoutClaims
}

/// Plain Models values only: canonical event JSON is opaque to the Core reducer here.
/// Checksums detect corruption; they do not authenticate the producer.
struct CalleeClaimEnvelope: Codable, Equatable, Sendable {
    static let schemaVersion = 1
    static let maximumClaims = 256
    static let maximumEvents = 16_384
    static let maximumCallees = 8_192
    // Deliberately stricter persistence budgets than the in-memory ledger.
    static let maximumEventBytes = 4 * 1024 * 1024
    static let maximumEncodedBytes = 24 * 1024 * 1024
    static let empty = Self(uncheckedEvents: [])
    let events: [Event]
    var isEmpty: Bool { events.isEmpty }

    struct Event: Codable, Equatable, Sendable {
        let canonicalBytes: Data
        let digest: String
        var sequence: UInt64 { header.sequence }
        var claimID: UUID { header.claimID }
        var kind: String { header.kind }
        var revision: Int { header.revision }
        private let header: Header

        private struct Header: Decodable, Equatable, Sendable {
            let sequence: UInt64
            let atMilliseconds: UInt64
            let claimID: UUID
            let kind: String
            let revision: Int
        }

        init(canonicalBytes: Data) throws {
            guard canonicalBytes.count <= CalleeClaimEnvelope.maximumEventBytes else {
                throw CalleeClaimEnvelopeError.eventTooLarge
            }
            do {
                // Reuse the package's byte-level duplicate-member admission before Foundation
                // can shadow any identifier; this does not guess nested Core value grammars.
                guard try !WorkspacePackageDuplicateKeyPreflight.scan(canonicalBytes).findings.anyObjectMember else {
                    throw CalleeClaimEnvelopeError.malformedEvent
                }
                header = try JSONDecoder().decode(Header.self, from: canonicalBytes)
                guard ["claimOpened", "outcomeRecorded", "claimRebound", "claimSuperseded"].contains(header.kind),
                      header.sequence > 0, header.revision > 0 else { throw CalleeClaimEnvelopeError.malformedEvent }
                try Self.checkShape(canonicalBytes)
            } catch let error as CalleeClaimEnvelopeError { throw error }
            catch { throw CalleeClaimEnvelopeError.malformedEvent }
            self.canonicalBytes = canonicalBytes
            digest = VerifiedAnnotationAuditCodec.sha256Hex(canonicalBytes)
        }

        private enum CodingKeys: String, CodingKey { case canonicalBytes, digest }
        init(from decoder: Decoder) throws {
            do {
                try CalleeClaimEnvelope.requireKeys(decoder, ["canonicalBytes", "digest"])
                let c = try decoder.container(keyedBy: CodingKeys.self)
                let encoded = try c.decode(String.self, forKey: .canonicalBytes)
                guard encoded.utf8.count <= ((CalleeClaimEnvelope.maximumEventBytes + 2) / 3) * 4 else {
                    throw CalleeClaimEnvelopeError.eventTooLarge
                }
                guard let bytes = Data(base64Encoded: encoded) else { throw CalleeClaimEnvelopeError.malformedEvent }
                try self.init(canonicalBytes: bytes)
                guard try c.decode(String.self, forKey: .digest) == digest else {
                    throw CalleeClaimEnvelopeError.digestMismatch
                }
            } catch let error as CalleeClaimEnvelopeError { throw error }
            catch { throw CalleeClaimEnvelopeError.malformedEvent }
        }
        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(canonicalBytes, forKey: .canonicalBytes)
            try c.encode(digest, forKey: .digest)
        }

        /// Package-side closed check of `binding.projectionEpoch` (the Core `VAProjectionStamp` is not
        /// visible to Models and its synthesized decoder would ignore unknown members). Exactly the five
        /// stamp members, a 64-hex digest, and a byte-identical canonical re-encode through the
        /// `VerifiedAnnotationProjectionIdentity` mirror. Structural only: the Store replay through the
        /// real types stays authoritative.
        private static func checkProjectionEpoch(_ value: Any) throws {
            guard let object = value as? [String: Any],
                  Set(object.keys) == ["workspaceID", "documentID", "installationID", "revision", "digest"] else {
                throw CalleeClaimEnvelopeError.malformedEvent
            }
            do {
                let data = try JSONSerialization.data(withJSONObject: object)
                let stamp = try JSONDecoder().decode(VerifiedAnnotationProjectionIdentity.self, from: data)
                guard VerifiedAnnotationAuditCodec.isSHA256(stamp.digest),
                      let again = try JSONSerialization.jsonObject(
                        with: VerifiedAnnotationAuditCodec.encode(stamp)) as? [String: Any],
                      NSDictionary(dictionary: again).isEqual(to: object) else {
                    throw CalleeClaimEnvelopeError.malformedEvent
                }
            } catch let error as CalleeClaimEnvelopeError { throw error }
            catch { throw CalleeClaimEnvelopeError.malformedEvent }
        }

        private static func checkShape(_ bytes: Data) throws {
            func object(_ value: Any, allowed: Set<String>) throws -> [String: Any] {
                guard let value = value as? [String: Any], Set(value.keys).isSubset(of: allowed) else {
                    throw CalleeClaimEnvelopeError.malformedEvent
                }
                return value
            }
            let e = try object(JSONSerialization.jsonObject(with: bytes), allowed: [
                "sequence", "atMilliseconds", "claimID", "kind", "revision", "binding", "inventory",
                "previousGeneration", "invalidatedCallees", "callee", "outcome", "reason", "bearing", "bodyDigest", "witness"
            ])
            let kind = e["kind"] as? String
            let outcome = kind == "outcomeRecorded"
            let rebound = kind == "claimRebound"
            let inventory = kind == "claimOpened" || kind == "claimSuperseded"
            guard (e["binding"] != nil) == !outcome, (e["inventory"] != nil) == inventory,
                  (e["previousGeneration"] != nil) == rebound, (e["invalidatedCallees"] != nil) == rebound,
                  (e["callee"] != nil) == outcome, (e["outcome"] != nil) == outcome,
                  (e["reason"] != nil) == outcome else { throw CalleeClaimEnvelopeError.malformedEvent }
            if !outcome && ["bearing", "bodyDigest", "witness"].contains(where: { e[$0] != nil }) {
                throw CalleeClaimEnvelopeError.malformedEvent
            }
            if outcome {
                guard let value = e["outcome"] as? String, ["examined", "irrelevant", "deferred"].contains(value),
                      let reason = e["reason"] as? String, (1...2048).contains(reason.utf8.count) else {
                    throw CalleeClaimEnvelopeError.malformedEvent
                }
                if value != "examined" && ["bearing", "bodyDigest", "witness"].contains(where: { e[$0] != nil }) {
                    throw CalleeClaimEnvelopeError.malformedEvent
                }
            }
            if let value = e["binding"] {
                let binding = try object(value, allowed: ["imageOwner", "slot", "function", "analysisGeneration", "projectionEpoch", "inventoryDigest"])
                if let epoch = binding["projectionEpoch"] { try checkProjectionEpoch(epoch) }
            }
            if let value = e["witness"] {
                _ = try object(value, allowed: ["command", "generation", "sequence"])
            }
            if let value = e["invalidatedCallees"] {
                guard let list = value as? [Any], list.count <= CalleeClaimEnvelope.maximumCallees else {
                    throw CalleeClaimEnvelopeError.tooManyCallees
                }
            }
            if let value = e["inventory"] {
                let i = try object(value, allowed: ["function", "completeness", "callees", "indirect", "unresolvedIndirectCallSites", "limitations", "inventoryDigest"])
                for key in ["callees", "indirect"] {
                    guard let entries = i[key] as? [Any] else { throw CalleeClaimEnvelopeError.malformedEvent }
                    guard entries.count <= CalleeClaimEnvelope.maximumCallees else { throw CalleeClaimEnvelopeError.tooManyCallees }
                    for entry in entries {
                        _ = try object(entry, allowed: key == "callees"
                            ? ["callee", "kind", "name", "callSiteCount", "callSites", "callSitesTruncated", "containingFunction", "offsetInFunction"]
                            : ["callSite", "target", "targetName", "scope"])
                    }
                }
            }
        }
    }

    private init(uncheckedEvents: [Event]) { events = uncheckedEvents }
    init(events: [Event]) throws {
        self.events = events
        try validate()
    }
    func validate() throws {
        guard events.count <= Self.maximumEvents else { throw CalleeClaimEnvelopeError.tooManyEvents }
        var ids = Set<UUID>()
        var revisions: [UUID: Int] = [:]
        var encodedByteLowerBound = 0
        for (index, event) in events.enumerated() {
            encodedByteLowerBound += ((event.canonicalBytes.count + 2) / 3) * 4
            guard encodedByteLowerBound <= Self.maximumEncodedBytes else {
                throw CalleeClaimEnvelopeError.envelopeTooLarge
            }
            guard event.sequence == UInt64(index + 1) else { throw CalleeClaimEnvelopeError.invalidLedger }
            if event.kind == "claimOpened" {
                guard ids.insert(event.claimID).inserted else { throw CalleeClaimEnvelopeError.duplicateClaimID(event.claimID) }
                guard ids.count <= Self.maximumClaims else { throw CalleeClaimEnvelopeError.tooManyClaims }
                guard event.revision == 1 else { throw CalleeClaimEnvelopeError.invalidLedger }
                revisions[event.claimID] = 1
            } else {
                guard let current = revisions[event.claimID] else { throw CalleeClaimEnvelopeError.invalidLedger }
                if event.kind == "claimSuperseded" {
                    guard current < Int.max, event.revision == current + 1 else {
                        throw CalleeClaimEnvelopeError.invalidLedger
                    }
                    revisions[event.claimID] = event.revision
                } else {
                    guard event.revision == current else { throw CalleeClaimEnvelopeError.invalidLedger }
                }
            }
        }
        guard try VerifiedAnnotationAuditCodec.encode(Wire(schemaVersion: Self.schemaVersion, events: events)).count <= Self.maximumEncodedBytes else {
            throw CalleeClaimEnvelopeError.envelopeTooLarge
        }
    }
    private struct Wire: Encodable {
        let schemaVersion: Int
        let events: [Event]
    }
    private enum CodingKeys: String, CodingKey { case schemaVersion, events }
    init(from decoder: Decoder) throws {
        do {
            try Self.requireKeys(decoder, ["schemaVersion", "events"])
            let c = try decoder.container(keyedBy: CodingKeys.self)
            let version = try c.decode(Int.self, forKey: .schemaVersion)
            guard version == Self.schemaVersion else { throw CalleeClaimEnvelopeError.unsupportedSchema(version) }
            var list = try c.nestedUnkeyedContainer(forKey: .events)
            var decoded: [Event] = []
            var bytes = 0
            while !list.isAtEnd {
                guard decoded.count < Self.maximumEvents else { throw CalleeClaimEnvelopeError.tooManyEvents }
                let event = try list.decode(Event.self)
                bytes += ((event.canonicalBytes.count + 2) / 3) * 4
                guard bytes <= Self.maximumEncodedBytes else { throw CalleeClaimEnvelopeError.envelopeTooLarge }
                decoded.append(event)
            }
            try self.init(events: decoded)
        } catch let error as CalleeClaimEnvelopeError { throw error }
        catch { throw CalleeClaimEnvelopeError.malformedEnvelope }
    }
    func encode(to encoder: Encoder) throws {
        try validate()
        try Wire(schemaVersion: Self.schemaVersion, events: events).encode(to: encoder)
    }
    private static func requireKeys(_ decoder: Decoder, _ keys: Set<String>) throws {
        struct Key: CodingKey {
            let stringValue: String
            let intValue: Int? = nil
            init?(stringValue: String) { self.stringValue = stringValue }
            init?(intValue: Int) { return nil }
        }
        let c = try decoder.container(keyedBy: Key.self)
        guard Set(c.allKeys.map(\.stringValue)) == keys else { throw CalleeClaimEnvelopeError.malformedEnvelope }
    }
}
