// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

/// Image virtual addresses are never JSON numbers or inferred file offsets.
public struct VAAddress64: Codable, Hashable, Comparable, Sendable, CustomStringConvertible {
    public let rawValue: UInt64
    public init(_ rawValue: UInt64) { self.rawValue = rawValue }
    public var description: String { "0x" + String(rawValue, radix: 16) }
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let text = try c.decode(String.self)
        guard text.hasPrefix("0x"), (3...18).contains(text.utf8.count),
              text.dropFirst(2).utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let value = UInt64(text.dropFirst(2), radix: 16),
              text == VAAddress64(value).description else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "Expected canonical hexadecimal UInt64 address")
        }
        rawValue = value
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(description)
    }
}

public enum VAVerificationError: Error, Equatable, Sendable {
    case invalidState(String)
    case invalidRequest(String)
    case busy
    case recoveryRequired
    case idempotencyConflict
    case staleProjection
    case unknownTarget
    /// An `addressType` edit or `addressFacts` query named a function entry. Types at function entries
    /// are not part of this class (VA-SCOPE ruling 5, DESIGN 2.2).
    case functionEntryTarget
    case unknownEvidence
    case mismatchedEvidence
    case incompleteEvidence
    case unsupportedMutation
    case unsupportedPublication
    case candidateMismatch(String)
    case budgetExceeded(String)
    case exhausted
    case cancelled
    case publicationFailed(String)
    case publicationIndeterminate(String)
}

public struct VATargetReference: Codable, Hashable, Sendable {
    public let componentID: UUID
    /// A function entry address. For an `addressType` edit this field holds a data address instead;
    /// the name is kept so existing Core types and encodings do not change.
    public let function: VAAddress64
    public init(componentID: UUID, function: VAAddress64) {
        self.componentID = componentID; self.function = function
    }
}

public struct VAProjectionStamp: Codable, Hashable, Sendable {
    public let workspaceID: UUID
    public let documentID: UUID
    public let installationID: UUID
    public let revision: UInt64
    public let digest: String
    public init(workspaceID: UUID, documentID: UUID, installationID: UUID, revision: UInt64, digest: String) {
        self.workspaceID = workspaceID; self.documentID = documentID
        self.installationID = installationID; self.revision = revision; self.digest = digest
    }
    public func validate() throws {
        guard VACanonicalJSON.isSHA256(digest) else { throw VAVerificationError.invalidState("invalid projection digest") }
    }
}

public enum VAARMArchitecture: String, Codable, Sendable { case arm64, arm64e }
public enum VAObservationCompleteness: String, Codable, Sendable { case complete, partial, unavailable }
public enum VAQueryKind: String, Codable, Sendable { case disassembly, functionFacts, annotations, directCalls, addressFacts }
/// `addressType` is a type name applied to a data address; `functionPrototype` carries a function signature.
public enum VAEditKind: String, Codable, Sendable { case functionName, functionComment, functionPrototype, addressType }

public struct VAFunctionProjection: Codable, Equatable, Sendable {
    public let address: VAAddress64
    public let originalName: String
    public var customName: String?
    public var customComment: String?
    /// Reference backend fixture data. Production adapters use MacScope's read authority.
    public let disassembly: String
    public let directCallees: [VAAddress64]
    public let directCallCompleteness: VAObservationCompleteness
    public init(address: VAAddress64, originalName: String, customName: String? = nil,
                customComment: String? = nil, disassembly: String,
                directCallees: [VAAddress64] = [], directCallCompleteness: VAObservationCompleteness = .complete) {
        self.address = address; self.originalName = originalName
        self.customName = customName; self.customComment = customComment; self.disassembly = disassembly
        self.directCallees = directCallees; self.directCallCompleteness = directCallCompleteness
    }
}

/// One data address the `addressFacts` query can describe (VA-SCOPE S3). `VAFunctionProjection` cannot hold it:
/// a data address is not a function. The native adapter only emits an entry for an address that lies inside a
/// segment of the component's slot, so an address with no entry is unknown to the coordinator.
public struct VAAddressProjection: Codable, Equatable, Sendable {
    public let address: VAAddress64
    /// Name of the slot segment that contains `address`.
    public let segment: String
    /// True when the address is a function entry (analysis function start or a forced procedure start).
    /// A type edit refuses such an address with a typed error.
    public let isFunctionEntry: Bool
    /// Baseline applied type name at the address; nil when none.
    public var appliedTypeName: String?
    public init(address: VAAddress64, segment: String, isFunctionEntry: Bool, appliedTypeName: String? = nil) {
        self.address = address; self.segment = segment
        self.isFunctionEntry = isFunctionEntry; self.appliedTypeName = appliedTypeName
    }
}

public struct VAComponentProjection: Codable, Equatable, Sendable {
    public let id: UUID
    public let imageSlot: Int
    public let binarySHA256: String
    public let sliceSHA256: String
    public let architecture: VAARMArchitecture
    /// Native adapters must include the existing analysis identity/generation in this field.
    public let analysisIdentity: String
    public var functions: [VAFunctionProjection]
    /// Data-address entries for `addressFacts` / `addressType`. nil (the default) is omitted from the
    /// encoding, so a projection without them keeps its existing stamp digest byte for byte.
    public var addresses: [VAAddressProjection]?
    public init(id: UUID, imageSlot: Int, binarySHA256: String, sliceSHA256: String,
                architecture: VAARMArchitecture, analysisIdentity: String, functions: [VAFunctionProjection],
                addresses: [VAAddressProjection]? = nil) {
        self.id = id; self.imageSlot = imageSlot; self.binarySHA256 = binarySHA256
        self.sliceSHA256 = sliceSHA256; self.architecture = architecture
        self.analysisIdentity = analysisIdentity; self.functions = functions; self.addresses = addresses
    }
}

public struct VAWorkspaceProjection: Codable, Equatable, Sendable {
    public let workspaceID: UUID
    public let documentID: UUID
    public let installationID: UUID
    public var revision: UInt64
    public var components: [VAComponentProjection]
    public init(workspaceID: UUID, documentID: UUID, installationID: UUID,
                revision: UInt64 = 0, components: [VAComponentProjection]) {
        self.workspaceID = workspaceID; self.documentID = documentID
        self.installationID = installationID; self.revision = revision; self.components = components
    }
    public func validate() throws {
        guard !components.isEmpty, components.count <= 128,
              Set(components.map(\.id)).count == components.count,
              Set(components.map(\.imageSlot)).count == components.count else {
            throw VAVerificationError.invalidState("duplicate, empty, or excessive component inventory")
        }
        var total = 0
        for component in components {
            guard component.imageSlot >= 0, VACanonicalJSON.isSHA256(component.binarySHA256),
                  VACanonicalJSON.isSHA256(component.sliceSHA256),
                  !component.analysisIdentity.isEmpty, component.analysisIdentity.utf8.count <= 1024,
                  component.functions.count <= 100_000,
                  Set(component.functions.map(\.address)).count == component.functions.count else {
                throw VAVerificationError.invalidState("invalid component identity or function inventory")
            }
            total += component.functions.count
            guard total <= 100_000 else { throw VAVerificationError.budgetExceeded("function inventory") }
            if let addresses = component.addresses {
                let functionAddresses = Set(component.functions.map(\.address))
                guard addresses.count <= 100_000,
                      Set(addresses.map(\.address)).count == addresses.count,
                      addresses.allSatisfy({ entry in
                          (1...256).contains(entry.segment.utf8.count) && !entry.segment.contains("\0")
                              && (!functionAddresses.contains(entry.address) || entry.isFunctionEntry)
                              && (entry.appliedTypeName.map({
                                  !$0.isEmpty && $0.utf8.count <= 256
                                      && !$0.contains("\0") && !$0.contains("\n") && !$0.contains("\r")
                              }) ?? true)
                      }) else {
                    throw VAVerificationError.invalidState("invalid address inventory")
                }
            }
            for function in component.functions {
                guard function.originalName.utf8.count <= 4096, function.disassembly.utf8.count <= 1_048_576,
                      function.directCallees.count <= 10_000,
                      Set(function.directCallees).count == function.directCallees.count,
                      function.customName.map({ !$0.isEmpty && $0.utf8.count <= 1024 && !$0.contains("\0") && !$0.contains("\n") }) ?? true,
                      function.customComment.map({ $0.utf8.count <= 65_536 && !$0.contains("\0") }) ?? true else {
                    throw VAVerificationError.invalidState("invalid function data")
                }
            }
        }
    }
    public func function(_ target: VATargetReference) -> VAFunctionProjection? {
        components.first { $0.id == target.componentID }?.functions.first { $0.address == target.function }
    }
    /// The data-address entry for `target.function` (an address for `addressType`), if the adapter emitted one.
    public func addressEntry(_ target: VATargetReference) -> VAAddressProjection? {
        components.first { $0.id == target.componentID }?.addresses?.first { $0.address == target.function }
    }
    /// A target is known when it is a function or has an address entry (used for evidence retention).
    public func knows(_ target: VATargetReference) -> Bool {
        function(target) != nil || addressEntry(target) != nil
    }
    /// Target resolution for a query. `addressFacts` resolves through an address entry and refuses a
    /// function entry; every other query keeps the function-only rule.
    public func requireTarget(_ target: VATargetReference, query: VAQueryKind) throws {
        if query == .addressFacts { try requireAddressTarget(target) }
        else if function(target) == nil { throw VAVerificationError.unknownTarget }
    }
    /// Target resolution for an edit. `addressType` resolves through an address entry and refuses a
    /// function entry; every other kind keeps the function-only rule.
    public func requireTarget(_ target: VATargetReference, edit: VAEditKind) throws {
        if edit == .addressType { try requireAddressTarget(target) }
        else if function(target) == nil { throw VAVerificationError.unknownTarget }
    }
    private func requireAddressTarget(_ target: VATargetReference) throws {
        guard let entry = addressEntry(target) else { throw VAVerificationError.unknownTarget }
        guard !entry.isFunctionEntry else { throw VAVerificationError.functionEntryTarget }
    }
    public func stamp() throws -> VAProjectionStamp {
        try validate()
        var ordered = self
        ordered.components.sort { $0.imageSlot < $1.imageSlot }
        for c in ordered.components.indices {
            ordered.components[c].functions.sort { $0.address < $1.address }
            ordered.components[c].addresses?.sort { $0.address < $1.address }
        }
        return VAProjectionStamp(workspaceID: workspaceID, documentID: documentID, installationID: installationID,
                               revision: revision, digest: VASHA256Digest.hex(try VACanonicalJSON.encode(ordered)))
    }
}

public struct VANativeObservation: Codable, Equatable, Sendable {
    public let stamp: VAProjectionStamp
    public let target: VATargetReference
    public let query: VAQueryKind
    public let completeness: VAObservationCompleteness
    public let content: String
    public let limitation: String?
    public init(stamp: VAProjectionStamp, target: VATargetReference, query: VAQueryKind,
                completeness: VAObservationCompleteness, content: String, limitation: String? = nil) {
        self.stamp = stamp; self.target = target; self.query = query
        self.completeness = completeness; self.content = content; self.limitation = limitation
    }
}

/// A serialized record, not a bearer credential. Only the trusted authority resolves its opaque ID.
public struct VAEvidenceRecord: Codable, Equatable, Sendable {
    public let id: UUID
    public let observation: VANativeObservation
    public let capturedAt: Date
    public init(id: UUID, observation: VANativeObservation, capturedAt: Date) {
        self.id = id; self.observation = observation; self.capturedAt = VACanonicalJSON.normalizedDate(capturedAt)
    }
}

public struct VAEditIntent: Codable, Equatable, Sendable {
    public let target: VATargetReference
    public let kind: VAEditKind
    public let value: String?
    public let evidenceIDs: [UUID]
    public init(target: VATargetReference, kind: VAEditKind, value: String?, evidenceIDs: [UUID]) {
        self.target = target; self.kind = kind; self.value = value; self.evidenceIDs = evidenceIDs
    }
}

public struct VAMutationRequest: Codable, Equatable, Sendable {
    public let id: UUID
    public let base: VAProjectionStamp
    public let edits: [VAEditIntent]
    public let rationale: String
    public let findingID: UUID?
    public init(id: UUID = UUID(), base: VAProjectionStamp, edits: [VAEditIntent], rationale: String, findingID: UUID? = nil) {
        self.id = id; self.base = base; self.edits = edits; self.rationale = rationale; self.findingID = findingID
    }
    public func digest() throws -> String {
        try validateRetentionBounds()
        return VASHA256Digest.hex(try VACanonicalJSON.encode(self))
    }
    /// Resource limits apply even to malformed requests retained as rejected audit records.
    /// This guard must run before request hashing, both on live ingress and decoded history.
    public func validateRetentionBounds() throws {
        guard base.digest.utf8.count <= 64, edits.count <= 64, rationale.utf8.count <= 16_384,
              edits.allSatisfy({ $0.evidenceIDs.count <= 32 && ($0.value?.utf8.count ?? 0) <= 65_536 }) else {
            throw VAVerificationError.budgetExceeded("request")
        }
    }
    public func validateShape() throws {
        try validateRetentionBounds()
        try base.validate()
        guard !edits.isEmpty, edits.count <= 64, !rationale.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              rationale.utf8.count <= 16_384 else { throw VAVerificationError.invalidRequest("invalid edit count or rationale") }
        var keys = Set<String>()
        for edit in edits {
            let key = "\(edit.target.componentID)/\(edit.target.function)/\(edit.kind.rawValue)"
            guard keys.insert(key).inserted, !edit.evidenceIDs.isEmpty, edit.evidenceIDs.count <= 32,
                  Set(edit.evidenceIDs).count == edit.evidenceIDs.count else {
                throw VAVerificationError.invalidRequest("duplicate edit or invalid evidence list")
            }
            switch edit.kind {
            case .functionName:
                guard edit.value.map({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                    $0.utf8.count <= 1024 && !$0.contains("\n") && !$0.contains("\r") && !$0.contains("\0") }) ?? true
                else { throw VAVerificationError.invalidRequest("invalid function name") }
            case .functionComment:
                guard edit.value.map({ $0.utf8.count <= 65_536 && !$0.contains("\0") }) ?? true
                else { throw VAVerificationError.invalidRequest("invalid function comment") }
            case .functionPrototype:
                // Core is portable: bounds only, never structure.
                guard edit.value.map({ $0.utf8.count <= 16_384 && !$0.contains("\0") }) ?? true
                else { throw VAVerificationError.invalidRequest("invalid function prototype") }
            case .addressType:
                // nil clears the type. A present name must be non-blank and at most 256 UTF-8 bytes.
                guard edit.value.map({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                    $0.utf8.count <= 256 && !$0.contains("\n") && !$0.contains("\r") && !$0.contains("\0") }) ?? true
                else { throw VAVerificationError.invalidRequest("invalid address type") }
            }
        }
    }
}

public enum VAReceiptDecision: String, Codable, Sendable { case accepted, rejected }
public enum VAMechanicalStatus: String, Codable, Sendable { case notVerified, candidateReadbackVerified }
public enum VAPersistenceStatus: String, Codable, Sendable { case notApplicable, pendingFreshProcessCheckpoint }
public enum VASemanticStatus: String, Codable, Sendable { case notReviewed }

public struct VAVerificationReceipt: Codable, Equatable, Sendable {
    public let request: VAMutationRequest
    public let requestDigest: String
    public let decision: VAReceiptDecision
    public let before: VAProjectionStamp
    public let after: VAProjectionStamp?
    public let mechanical: VAMechanicalStatus
    public let persistence: VAPersistenceStatus
    public let semantic: VASemanticStatus
    public let failure: String?
    public let recovery: String?
    public let recordedAt: Date
    public init(request: VAMutationRequest, decision: VAReceiptDecision, before: VAProjectionStamp,
                after: VAProjectionStamp?, mechanical: VAMechanicalStatus, persistence: VAPersistenceStatus,
                failure: String? = nil, recovery: String? = nil, recordedAt: Date = Date()) throws {
        guard failure.map({ $0.utf8.count <= 4096 }) ?? true,
              recovery.map({ $0.utf8.count <= 4096 }) ?? true else {
            throw VAVerificationError.budgetExceeded("receipt diagnostics")
        }
        self.request = request; self.requestDigest = try request.digest(); self.decision = decision
        self.before = before; self.after = after; self.mechanical = mechanical; self.persistence = persistence
        self.semantic = .notReviewed; self.failure = failure; self.recovery = recovery
        self.recordedAt = VACanonicalJSON.normalizedDate(recordedAt)
    }
}

public struct VAVerificationState: Codable, Sendable {
    public var schemaVersion: Int = 1
    public var projection: VAWorkspaceProjection
    public var evidence: [VAEvidenceRecord]
    public var receipts: [VAVerificationReceipt]
    public init(projection: VAWorkspaceProjection, evidence: [VAEvidenceRecord] = [], receipts: [VAVerificationReceipt] = []) {
        self.projection = projection; self.evidence = evidence; self.receipts = receipts
    }
    public func validate() throws {
        guard schemaVersion == 1, evidence.count <= 10_000, receipts.count <= 10_000,
              Set(evidence.map(\.id)).count == evidence.count,
              Set(receipts.map { $0.request.id }).count == receipts.count else {
            throw VAVerificationError.invalidState("unsupported schema, duplicate IDs, or exhausted ledger")
        }
        try projection.validate()
        let current = try projection.stamp()
        for record in evidence {
            try record.observation.stamp.validate()
            let observation = record.observation
            guard observation.stamp.workspaceID == current.workspaceID,
                  observation.stamp.documentID == current.documentID,
                  observation.stamp.revision <= current.revision,
                  (observation.stamp != current || projection.knows(observation.target)),
                  observation.content.utf8.count <= 1_048_576,
                  observation.limitation.map({ !$0.isEmpty && $0.utf8.count <= 4096 }) ?? true,
                  observation.completeness == .complete || observation.limitation != nil else {
                throw VAVerificationError.invalidState("invalid evidence record")
            }
        }
        let evidenceByID = Dictionary(uniqueKeysWithValues: evidence.map { ($0.id, $0) })
        for receipt in receipts {
            try receipt.request.validateRetentionBounds()
            guard receipt.failure.map({ $0.utf8.count <= 4096 }) ?? true,
                  receipt.recovery.map({ $0.utf8.count <= 4096 }) ?? true else {
                throw VAVerificationError.budgetExceeded("receipt diagnostics")
            }
            try receipt.before.validate()
            guard receipt.requestDigest == (try receipt.request.digest()),
                  receipt.before.workspaceID == current.workspaceID,
                  receipt.before.documentID == current.documentID,
                  receipt.before.revision <= current.revision else {
                throw VAVerificationError.invalidState("invalid receipt identity")
            }
            if receipt.decision == .accepted {
                try receipt.request.validateShape()
                guard receipt.before == receipt.request.base, let after = receipt.after,
                      after.workspaceID == current.workspaceID, after.documentID == current.documentID,
                      after.installationID == receipt.before.installationID, VACanonicalJSON.isSHA256(after.digest),
                      receipt.before.revision < UInt64.max, after.revision == receipt.before.revision + 1,
                      after.revision <= current.revision,
                      receipt.mechanical == .candidateReadbackVerified,
                      receipt.persistence == .pendingFreshProcessCheckpoint, receipt.failure == nil
                else { throw VAVerificationError.invalidState("invalid accepted receipt") }
                for edit in receipt.request.edits {
                    for id in edit.evidenceIDs {
                        guard let record = evidenceByID[id] else { throw VAVerificationError.unknownEvidence }
                        try VAEvidenceEligibility.requireMutationEvidence(record, for: edit.target, kind: edit.kind, at: receipt.before)
                    }
                }
            } else {
                guard receipt.after == nil, receipt.mechanical == .notVerified,
                      receipt.persistence == .notApplicable, receipt.failure?.isEmpty == false else {
                    throw VAVerificationError.invalidState("invalid rejected receipt")
                }
            }
        }
        _ = try VAAcceptedReceiptHistory(state: self)
    }
}

public enum VACanonicalJSON {
    public static func normalizedDate(_ date: Date) -> Date {
        Date(timeIntervalSince1970: floor(date.timeIntervalSince1970 * 1000) / 1000)
    }
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return try encoder.encode(value)
    }
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try VAStrictJSON.validate(data)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(type, from: data)
    }
    public static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}
