// Native-original Core value types for per-claim callee coverage (roadmap VI3, slice A); see PROVENANCE.md.
import Foundation

// MARK: - Vocabulary

/// How a direct call target is classified. Derived from analysis tables by the inventory reader (slice B),
/// never from a name guess alone. `unnamed` carries no name.
public enum VACalleeKind: String, Codable, Sendable, CaseIterable { case function, interior, stub, external, unnamed }

public enum VACalleeOutcomeKind: String, Codable, Sendable, CaseIterable { case examined, irrelevant, deferred }

/// Optional bearing of an examined callee on the parent claim. Never blocks closure.
public enum VACalleeBearing: String, Codable, Sendable, CaseIterable { case supports, contradicts, neutral }

public enum VACalleeClaimStatus: String, Codable, Sendable, CaseIterable { case open, closed, stale }

/// The four stale rows of the classification table (the fifth row is "current", reported as no kind).
public enum VACalleeStaleKind: String, Codable, Sendable, CaseIterable {
    case generationAdvanced, inventoryChanged, imageChanged, functionGone
}

public enum VACalleeClaimError: Error, Equatable, Sendable {
    case invalid(String)
    /// The inventory is not `complete`; a claim is never opened over a partial or unavailable list.
    case inventoryUnavailable
    case claimLimit
    case eventLimit
    case unknownClaim
    case duplicateClaim
    case calleeNotInClaim(VAAddress64)
    case outcomeInvalid(String)
    case claimStale(VACalleeStaleKind)
    /// Rebind is only valid for `generationAdvanced`; nil means the claim is current.
    case notRebindable(VACalleeStaleKind?)
}

public enum VACalleeClaimLimits {
    public static let maximumClaims = 256
    public static let maximumEvents = 16_384
    public static let maximumCallees = 8_192
    public static let maximumCallSites = 16
    public static let minimumReasonBytes = 1
    public static let maximumReasonBytes = 2_048
    public static let maximumNameBytes = 1_024
    public static let maximumLimitations = 64
    public static let maximumLimitationBytes = 256
    public static let maximumScopeBytes = 256
    public static let maximumCommandBytes = 64
    public static let maximumUnresolvedIndirectCallSites = 1_000_000
}

// MARK: - Closed-key decoding

private struct VAClaimDynamicKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

/// Rejects keys the type does not declare, so a newer or hand-edited payload fails closed.
private func vaRejectUnknownKeys(_ decoder: Decoder, allowed: Set<String>) throws {
    let container = try decoder.container(keyedBy: VAClaimDynamicKey.self)
    for key in container.allKeys where !allowed.contains(key.stringValue) {
        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                debugDescription: "unknown key \(key.stringValue)"))
    }
}

private func vaCheck(_ condition: Bool, _ message: @autoclosure () -> String) throws {
    guard condition else { throw VACalleeClaimError.invalid(message()) }
}

// MARK: - Inventory model (slice B fills these)

public struct VACalleeInventoryEntry: Codable, Hashable, Sendable {
    /// Identity: the raw call target address.
    public let callee: VAAddress64
    public let kind: VACalleeKind
    /// Display name; nil for `unnamed` and whenever two kinds were plausible.
    public let name: String?
    public let callSiteCount: Int
    /// First <= 16 call sites, ascending.
    public let callSites: [VAAddress64]
    public let callSitesTruncated: Bool
    /// `interior` only: the known function that contains the target and the offset from its start.
    public let containingFunction: VAAddress64?
    public let offsetInFunction: UInt64?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case callee, kind, name, callSiteCount, callSites, callSitesTruncated, containingFunction, offsetInFunction
    }

    public init(callee: VAAddress64, kind: VACalleeKind, name: String? = nil, callSiteCount: Int,
                callSites: [VAAddress64], callSitesTruncated: Bool,
                containingFunction: VAAddress64? = nil, offsetInFunction: UInt64? = nil) {
        self.callee = callee; self.kind = kind; self.name = name; self.callSiteCount = callSiteCount
        self.callSites = callSites; self.callSitesTruncated = callSitesTruncated
        self.containingFunction = containingFunction; self.offsetInFunction = offsetInFunction
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        callee = try c.decode(VAAddress64.self, forKey: .callee)
        kind = try c.decode(VACalleeKind.self, forKey: .kind)
        name = try c.decodeIfPresent(String.self, forKey: .name)
        callSiteCount = try c.decode(Int.self, forKey: .callSiteCount)
        callSites = try c.decode([VAAddress64].self, forKey: .callSites)
        callSitesTruncated = try c.decode(Bool.self, forKey: .callSitesTruncated)
        containingFunction = try c.decodeIfPresent(VAAddress64.self, forKey: .containingFunction)
        offsetInFunction = try c.decodeIfPresent(UInt64.self, forKey: .offsetInFunction)
        try validate()
    }

    public func validate() throws {
        try vaCheck(callSiteCount >= 1, "callee has no call site")
        try vaCheck(callSites.count == min(callSiteCount, VACalleeClaimLimits.maximumCallSites),
                    "call site list does not match the count and the 16-site cap")
        try vaCheck(zip(callSites, callSites.dropFirst()).allSatisfy { $0.0 < $0.1 },
                    "call sites are not strictly ascending")
        try vaCheck(callSitesTruncated == (callSiteCount > callSites.count), "truncation flag disagrees with the count")
        if let name {
            try vaCheck((1...VACalleeClaimLimits.maximumNameBytes).contains(name.utf8.count), "callee name length")
            try vaCheck(kind != .unnamed, "an unnamed callee carries no name")
        }
        if kind == .interior {
            guard let containingFunction, let offsetInFunction, offsetInFunction > 0 else {
                throw VACalleeClaimError.invalid("interior callee needs a containing function and a nonzero offset")
            }
            let (sum, overflow) = containingFunction.rawValue.addingReportingOverflow(offsetInFunction)
            try vaCheck(!overflow && sum == callee.rawValue, "interior offset does not reach the callee")
        } else {
            try vaCheck(containingFunction == nil && offsetInFunction == nil, "only an interior callee carries a container")
        }
    }
}

/// Advisory indirect-call entry. Resolved targets may receive outcomes but are never required to close.
public struct VACalleeIndirectEntry: Codable, Hashable, Sendable {
    public let callSite: VAAddress64
    public let target: VAAddress64
    public let targetName: String?
    /// `function` or `type:<name>`.
    public let scope: String

    private enum CodingKeys: String, CodingKey, CaseIterable { case callSite, target, targetName, scope }

    public init(callSite: VAAddress64, target: VAAddress64, targetName: String? = nil, scope: String) {
        self.callSite = callSite; self.target = target; self.targetName = targetName; self.scope = scope
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        callSite = try c.decode(VAAddress64.self, forKey: .callSite)
        target = try c.decode(VAAddress64.self, forKey: .target)
        targetName = try c.decodeIfPresent(String.self, forKey: .targetName)
        scope = try c.decode(String.self, forKey: .scope)
        try validate()
    }

    public func validate() throws {
        try vaCheck((1...VACalleeClaimLimits.maximumScopeBytes).contains(scope.utf8.count), "indirect scope length")
        if let targetName {
            try vaCheck((1...VACalleeClaimLimits.maximumNameBytes).contains(targetName.utf8.count), "indirect target name length")
        }
    }
}

public struct VACalleeInventory: Codable, Equatable, Sendable {
    public let function: VAAddress64
    public let completeness: VAObservationCompleteness
    /// Required set: distinct direct call targets, strictly ascending by address, <= 8,192.
    public let callees: [VACalleeInventoryEntry]
    /// Advisory resolved indirect targets, <= 8,192.
    public let indirect: [VACalleeIndirectEntry]
    /// Permanent limitation: indirect call sites that could not be resolved (never expanded into guessed callees).
    public let unresolvedIndirectCallSites: Int
    /// Named limitations such as `tailCallsNotInventoried`; sorted, unique, each 1...256 bytes.
    public let limitations: [String]
    /// SHA-256 over the sorted (call site, target) pairs and the limitations; see `digest(callEdges:limitations:)`.
    public let inventoryDigest: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case function, completeness, callees, indirect, unresolvedIndirectCallSites, limitations, inventoryDigest
    }

    public init(function: VAAddress64, completeness: VAObservationCompleteness = .complete,
                callees: [VACalleeInventoryEntry], indirect: [VACalleeIndirectEntry] = [],
                unresolvedIndirectCallSites: Int = 0, limitations: [String] = [], inventoryDigest: String) {
        self.function = function; self.completeness = completeness; self.callees = callees
        self.indirect = indirect; self.unresolvedIndirectCallSites = unresolvedIndirectCallSites
        self.limitations = limitations; self.inventoryDigest = inventoryDigest
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        function = try c.decode(VAAddress64.self, forKey: .function)
        completeness = try c.decode(VAObservationCompleteness.self, forKey: .completeness)
        callees = try c.decode([VACalleeInventoryEntry].self, forKey: .callees)
        indirect = try c.decode([VACalleeIndirectEntry].self, forKey: .indirect)
        unresolvedIndirectCallSites = try c.decode(Int.self, forKey: .unresolvedIndirectCallSites)
        limitations = try c.decode([String].self, forKey: .limitations)
        inventoryDigest = try c.decode(String.self, forKey: .inventoryDigest)
        try validate()
    }

    /// A leaf is a complete, empty direct set with nothing else on the claim. An empty list that carries any
    /// limitation, unresolved indirect site or advisory indirect target is not proof of a leaf.
    public var isLeaf: Bool {
        completeness == .complete && callees.isEmpty && indirect.isEmpty
            && unresolvedIndirectCallSites == 0 && limitations.isEmpty
    }

    public func validate() throws {
        try vaCheck(callees.count <= VACalleeClaimLimits.maximumCallees, "too many callees")
        try vaCheck(indirect.count <= VACalleeClaimLimits.maximumCallees, "too many indirect entries")
        try vaCheck(Set(indirect).count == indirect.count, "duplicate indirect entry")
        try vaCheck(zip(callees, callees.dropFirst()).allSatisfy { $0.0.callee < $0.1.callee },
                    "callees are not strictly ascending by address")
        for entry in callees { try entry.validate() }
        for entry in indirect { try entry.validate() }
        try vaCheck((0...VACalleeClaimLimits.maximumUnresolvedIndirectCallSites).contains(unresolvedIndirectCallSites),
                    "unresolved indirect call site count")
        try vaCheck(limitations.count <= VACalleeClaimLimits.maximumLimitations, "too many limitations")
        try vaCheck(limitations.allSatisfy { (1...VACalleeClaimLimits.maximumLimitationBytes).contains($0.utf8.count) },
                    "limitation length")
        try vaCheck(zip(limitations, limitations.dropFirst()).allSatisfy { $0.0 < $0.1 },
                    "limitations are not sorted and unique")
        try vaCheck(VACanonicalJSON.isSHA256(inventoryDigest), "invalid inventory digest")
        switch completeness {
        case .complete: break
        case .partial: try vaCheck(!limitations.isEmpty, "a partial inventory needs a limitation")
        case .unavailable:
            try vaCheck(callees.isEmpty && indirect.isEmpty && !limitations.isEmpty,
                        "an unavailable inventory reports no callees and needs a limitation")
        }
    }

    /// Order-independent digest of the root's (call site, target) pairs plus its limitations. Names, comments
    /// and overrides are deliberately not inputs.
    public static func digest(callEdges: [(site: VAAddress64, target: VAAddress64)],
                              limitations: [String]) throws -> String {
        struct Input: Encodable { let edges: [[String]]; let limitations: [String] }
        let sorted = callEdges.sorted { ($0.site, $0.target) < ($1.site, $1.target) }
        let input = Input(edges: sorted.map { [$0.site.description, $0.target.description] },
                          limitations: limitations.sorted())
        return VASHA256Digest.hex(try VACanonicalJSON.encode(input))
    }
}

// MARK: - Binding, witness, events

public struct VACalleeClaimBinding: Codable, Equatable, Sendable {
    public let imageOwner: UUID
    public let slot: Int
    public let function: VAAddress64
    public let analysisGeneration: UUID
    /// Carried and reported only; never gates in M4.
    public let projectionEpoch: VAProjectionStamp?
    public let inventoryDigest: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case imageOwner, slot, function, analysisGeneration, projectionEpoch, inventoryDigest
    }

    public init(imageOwner: UUID, slot: Int, function: VAAddress64, analysisGeneration: UUID,
                projectionEpoch: VAProjectionStamp? = nil, inventoryDigest: String) {
        self.imageOwner = imageOwner; self.slot = slot; self.function = function
        self.analysisGeneration = analysisGeneration; self.projectionEpoch = projectionEpoch
        self.inventoryDigest = inventoryDigest
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        imageOwner = try c.decode(UUID.self, forKey: .imageOwner)
        slot = try c.decode(Int.self, forKey: .slot)
        function = try c.decode(VAAddress64.self, forKey: .function)
        analysisGeneration = try c.decode(UUID.self, forKey: .analysisGeneration)
        projectionEpoch = try c.decodeIfPresent(VAProjectionStamp.self, forKey: .projectionEpoch)
        inventoryDigest = try c.decode(String.self, forKey: .inventoryDigest)
        try validate()
    }

    public func validate() throws {
        try vaCheck(slot >= 0, "negative image slot")
        try vaCheck(VACanonicalJSON.isSHA256(inventoryDigest), "invalid binding digest")
        do { try projectionEpoch?.validate() } catch { throw VACalleeClaimError.invalid("invalid projection epoch") }
    }

    fileprivate func sameTarget(as other: VACalleeClaimBinding) -> Bool {
        imageOwner == other.imageOwner && slot == other.slot && function == other.function
    }
}

/// Summary of the read that witnessed an examined callee (slice E fills it; optional here).
public struct VACalleeWitnessSummary: Codable, Hashable, Sendable {
    public let command: String
    public let generation: UUID
    public let sequence: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable { case command, generation, sequence }

    public init(command: String, generation: UUID, sequence: UInt64) {
        self.command = command; self.generation = generation; self.sequence = sequence
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        command = try c.decode(String.self, forKey: .command)
        generation = try c.decode(UUID.self, forKey: .generation)
        sequence = try c.decode(UInt64.self, forKey: .sequence)
        try validate()
    }

    public func validate() throws {
        try vaCheck((1...VACalleeClaimLimits.maximumCommandBytes).contains(command.utf8.count), "witness command length")
    }
}

public struct VACalleeClaimEvent: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case claimOpened, outcomeRecorded, claimRebound, claimSuperseded
    }

    public let sequence: UInt64
    public let atMilliseconds: UInt64
    public let claimID: UUID
    public let kind: Kind
    public let revision: Int
    /// opened, rebound, superseded.
    public let binding: VACalleeClaimBinding?
    /// opened, superseded.
    public let inventory: VACalleeInventory?
    /// rebound: the generation the claim was bound to before.
    public let previousGeneration: UUID?
    /// rebound: examined callees whose body changed and that return to open.
    public let invalidatedCallees: [VAAddress64]?
    /// outcomeRecorded.
    public let callee: VAAddress64?
    public let outcome: VACalleeOutcomeKind?
    public let reason: String?
    public let bearing: VACalleeBearing?
    public let bodyDigest: String?
    public let witness: VACalleeWitnessSummary?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case sequence, atMilliseconds, claimID, kind, revision, binding, inventory, previousGeneration
        case invalidatedCallees, callee, outcome, reason, bearing, bodyDigest, witness
    }

    public init(sequence: UInt64, atMilliseconds: UInt64, claimID: UUID, kind: Kind, revision: Int,
                binding: VACalleeClaimBinding? = nil, inventory: VACalleeInventory? = nil,
                previousGeneration: UUID? = nil, invalidatedCallees: [VAAddress64]? = nil,
                callee: VAAddress64? = nil, outcome: VACalleeOutcomeKind? = nil, reason: String? = nil,
                bearing: VACalleeBearing? = nil, bodyDigest: String? = nil, witness: VACalleeWitnessSummary? = nil) {
        self.sequence = sequence; self.atMilliseconds = atMilliseconds; self.claimID = claimID
        self.kind = kind; self.revision = revision; self.binding = binding; self.inventory = inventory
        self.previousGeneration = previousGeneration; self.invalidatedCallees = invalidatedCallees
        self.callee = callee; self.outcome = outcome; self.reason = reason; self.bearing = bearing
        self.bodyDigest = bodyDigest; self.witness = witness
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        sequence = try c.decode(UInt64.self, forKey: .sequence)
        atMilliseconds = try c.decode(UInt64.self, forKey: .atMilliseconds)
        claimID = try c.decode(UUID.self, forKey: .claimID)
        kind = try c.decode(Kind.self, forKey: .kind)
        revision = try c.decode(Int.self, forKey: .revision)
        binding = try c.decodeIfPresent(VACalleeClaimBinding.self, forKey: .binding)
        inventory = try c.decodeIfPresent(VACalleeInventory.self, forKey: .inventory)
        previousGeneration = try c.decodeIfPresent(UUID.self, forKey: .previousGeneration)
        invalidatedCallees = try c.decodeIfPresent([VAAddress64].self, forKey: .invalidatedCallees)
        callee = try c.decodeIfPresent(VAAddress64.self, forKey: .callee)
        outcome = try c.decodeIfPresent(VACalleeOutcomeKind.self, forKey: .outcome)
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
        bearing = try c.decodeIfPresent(VACalleeBearing.self, forKey: .bearing)
        bodyDigest = try c.decodeIfPresent(String.self, forKey: .bodyDigest)
        witness = try c.decodeIfPresent(VACalleeWitnessSummary.self, forKey: .witness)
        try validateShape()
    }

    /// Each kind carries exactly its own fields; anything else is rejected.
    public func validateShape() throws {
        try vaCheck(revision >= 1, "revision")
        let isOutcome = kind == .outcomeRecorded
        try vaCheck((binding != nil) == (kind != .outcomeRecorded), "binding presence")
        try vaCheck((inventory != nil) == (kind == .claimOpened || kind == .claimSuperseded), "inventory presence")
        try vaCheck((previousGeneration != nil) == (kind == .claimRebound), "previous generation presence")
        try vaCheck((invalidatedCallees != nil) == (kind == .claimRebound), "invalidated list presence")
        try vaCheck((callee != nil && outcome != nil && reason != nil) == isOutcome
                        && (callee != nil || outcome != nil || reason != nil) == isOutcome, "outcome fields")
        try vaCheck(isOutcome || (bearing == nil && bodyDigest == nil && witness == nil), "outcome-only fields")
        try binding?.validate()
        if let inventory {
            try inventory.validate()
            try vaCheck(inventory.function == binding?.function, "binding function differs from inventory function")
            try vaCheck(inventory.inventoryDigest == binding?.inventoryDigest, "binding digest differs from inventory digest")
            guard inventory.completeness == .complete else { throw VACalleeClaimError.inventoryUnavailable }
        }
        switch kind {
        case .claimOpened: try vaCheck(revision == 1, "opened revision must be 1")
        case .claimSuperseded: try vaCheck(revision >= 2, "superseded revision must be >= 2")
        case .claimRebound:
            let list = invalidatedCallees ?? []
            try vaCheck(list.count <= VACalleeClaimLimits.maximumCallees && Set(list).count == list.count,
                        "invalidated list")
        case .outcomeRecorded:
            try Self.validateOutcome(outcome: outcome!, reason: reason!, bearing: bearing)
            try vaCheck(outcome == .examined || (bodyDigest == nil && witness == nil), "witness fields on a non-examined outcome")
            if let bodyDigest { try vaCheck(VACanonicalJSON.isSHA256(bodyDigest), "invalid body digest") }
            try witness?.validate()
        }
    }

    fileprivate static func validateOutcome(outcome: VACalleeOutcomeKind, reason: String,
                                            bearing: VACalleeBearing?) throws {
        guard (VACalleeClaimLimits.minimumReasonBytes...VACalleeClaimLimits.maximumReasonBytes)
            .contains(reason.utf8.count) else {
            throw VACalleeClaimError.outcomeInvalid("reason must be 1...2048 bytes")
        }
        guard bearing == nil || outcome == .examined else {
            throw VACalleeClaimError.outcomeInvalid("bearing applies to examined outcomes only")
        }
    }
}

// MARK: - Derived reports

/// What the caller observes now about a claim's target. `inventory == nil` means the function no longer resolves.
public struct VACalleeClaimObservation: Equatable, Sendable {
    public let imageOwner: UUID
    public let generation: UUID
    public let projectionEpoch: VAProjectionStamp?
    public let inventory: VACalleeInventory?
    public init(imageOwner: UUID, generation: UUID, projectionEpoch: VAProjectionStamp? = nil,
                inventory: VACalleeInventory?) {
        self.imageOwner = imageOwner; self.generation = generation
        self.projectionEpoch = projectionEpoch; self.inventory = inventory
    }
}

public struct VACalleeStaleClassification: Equatable, Sendable {
    /// nil: the claim is current.
    public let kind: VACalleeStaleKind?
    public let rebindable: Bool
    /// `generationAdvanced` only: whether the projection epoch moved with the generation.
    public let projectionEpochMoved: Bool
    public let addedCallees: [VAAddress64]
    public let removedCallees: [VAAddress64]
}

public struct VACalleeOutcomeRecord: Equatable, Sendable {
    public let callee: VAAddress64
    public let outcome: VACalleeOutcomeKind
    public let reason: String
    public let bearing: VACalleeBearing?
    public let bodyDigest: String?
    public let witness: VACalleeWitnessSummary?
    public let sequence: UInt64
    public let revision: Int
}

public struct VACalleeCoverage: Codable, Equatable, Sendable {
    public let required: Int
    public let examined: Int
    public let irrelevant: Int
    public let deferred: Int
    /// Required callees with no latest outcome.
    public let open: Int
    /// Outcomes recorded on advisory indirect targets; never needed to close.
    public let advisoryRecorded: Int
    public let unresolvedIndirectCallSites: Int
    public let limitations: [String]
}

public struct VACalleeClaimReport: Equatable, Sendable {
    public let claimID: UUID
    public let revision: Int
    public let binding: VACalleeClaimBinding
    public let status: VACalleeClaimStatus
    public let staleKind: VACalleeStaleKind?
    public let rebindable: Bool
    public let projectionEpochMoved: Bool
    public let addedCallees: [VAAddress64]
    public let removedCallees: [VAAddress64]
    public let leaf: Bool
    public let closedWithDeferrals: Bool
    public let coverage: VACalleeCoverage
    public let openCallees: [VAAddress64]
    public let deferredCallees: [VAAddress64]
    public let contradictingCallees: [VAAddress64]
    public let reboundCount: Int
}

// MARK: - Ledger

/// Append-only, direct-only reducer over claim events. State is always derived by replaying `events`, so a
/// decoded ledger is validated by the same code path that built it. The ledger is a plain value: it owns no
/// store, journal or app dependency.
public struct CalleeClaimLedger: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public private(set) var events: [VACalleeClaimEvent]
    private var replay: Replay

    private enum CodingKeys: String, CodingKey, CaseIterable { case schemaVersion, events }

    public init() { events = []; replay = Replay() }

    /// Validates by replaying every event: consecutive sequence from 1, per-kind shape, caps and invariants.
    public init(events: [VACalleeClaimEvent]) throws {
        guard events.count <= VACalleeClaimLimits.maximumEvents else { throw VACalleeClaimError.eventLimit }
        var replay = Replay()
        for (index, event) in events.enumerated() {
            try replay.apply(event, expectedSequence: UInt64(index + 1))
        }
        self.events = events; self.replay = replay
    }

    public init(from decoder: Decoder) throws {
        try vaRejectUnknownKeys(decoder, allowed: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard try c.decode(Int.self, forKey: .schemaVersion) == Self.schemaVersion else {
            throw VACalleeClaimError.invalid("unsupported ledger schema version")
        }
        try self.init(events: try c.decode([VACalleeClaimEvent].self, forKey: .events))
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Self.schemaVersion, forKey: .schemaVersion)
        try c.encode(events, forKey: .events)
    }

    public static func decode(from data: Data) throws -> CalleeClaimLedger {
        try VACanonicalJSON.decode(CalleeClaimLedger.self, from: data)
    }

    public static func == (lhs: CalleeClaimLedger, rhs: CalleeClaimLedger) -> Bool { lhs.events == rhs.events }

    /// Claim IDs in the order they were first opened.
    public var claimIDs: [UUID] { replay.order }

    // MARK: Mutations

    public mutating func open(claimID: UUID, inventory: VACalleeInventory, binding: VACalleeClaimBinding,
                              atMilliseconds: UInt64) throws {
        try append(VACalleeClaimEvent(sequence: nextSequence, atMilliseconds: atMilliseconds, claimID: claimID,
                                      kind: .claimOpened, revision: 1, binding: binding, inventory: inventory))
    }

    /// Append-only: the latest outcome per callee wins, earlier ones stay in `events`. Refused against a stale claim.
    public mutating func recordOutcome(claimID: UUID, callee: VAAddress64, outcome: VACalleeOutcomeKind,
                                       reason: String, bearing: VACalleeBearing? = nil,
                                       bodyDigest: String? = nil, witness: VACalleeWitnessSummary? = nil,
                                       observed: VACalleeClaimObservation, atMilliseconds: UInt64) throws {
        guard let claim = replay.claims[claimID] else { throw VACalleeClaimError.unknownClaim }
        if let kind = try Self.classify(claim: claim, observed: observed).kind { throw VACalleeClaimError.claimStale(kind) }
        try VACalleeClaimEvent.validateOutcome(outcome: outcome, reason: reason, bearing: bearing)
        guard claim.knownCallees.contains(callee) else { throw VACalleeClaimError.calleeNotInClaim(callee) }
        try append(VACalleeClaimEvent(sequence: nextSequence, atMilliseconds: atMilliseconds, claimID: claimID,
                                      kind: .outcomeRecorded, revision: claim.revision, callee: callee,
                                      outcome: outcome, reason: reason, bearing: bearing,
                                      bodyDigest: bodyDigest, witness: witness))
    }

    /// Re-binds a `generationAdvanced` claim to the observed generation. Outcomes are preserved except the
    /// listed examined callees, which return to open.
    public mutating func rebind(claimID: UUID, observed: VACalleeClaimObservation,
                                invalidatedCallees: [VAAddress64] = [], atMilliseconds: UInt64) throws {
        guard let claim = replay.claims[claimID] else { throw VACalleeClaimError.unknownClaim }
        let classification = try Self.classify(claim: claim, observed: observed)
        guard classification.kind == .generationAdvanced else {
            throw VACalleeClaimError.notRebindable(classification.kind)
        }
        let old = claim.binding
        let rebound = VACalleeClaimBinding(imageOwner: old.imageOwner, slot: old.slot, function: old.function,
                                           analysisGeneration: observed.generation,
                                           projectionEpoch: observed.projectionEpoch,
                                           inventoryDigest: old.inventoryDigest)
        try append(VACalleeClaimEvent(sequence: nextSequence, atMilliseconds: atMilliseconds, claimID: claimID,
                                      kind: .claimRebound, revision: claim.revision, binding: rebound,
                                      previousGeneration: old.analysisGeneration,
                                      invalidatedCallees: invalidatedCallees))
    }

    /// Opens revision n+1 over a fresh inventory with every callee open. Earlier outcomes stay readable through
    /// `priorOutcomes` and never satisfy the new revision.
    public mutating func supersede(claimID: UUID, inventory: VACalleeInventory, binding: VACalleeClaimBinding,
                                   atMilliseconds: UInt64) throws {
        guard let claim = replay.claims[claimID] else { throw VACalleeClaimError.unknownClaim }
        try append(VACalleeClaimEvent(sequence: nextSequence, atMilliseconds: atMilliseconds, claimID: claimID,
                                      kind: .claimSuperseded, revision: claim.revision + 1,
                                      binding: binding, inventory: inventory))
    }

    // MARK: Reads

    public func classify(claimID: UUID, observed: VACalleeClaimObservation) throws -> VACalleeStaleClassification {
        guard let claim = replay.claims[claimID] else { throw VACalleeClaimError.unknownClaim }
        return try Self.classify(claim: claim, observed: observed)
    }

    public func report(claimID: UUID, observed: VACalleeClaimObservation) throws -> VACalleeClaimReport {
        guard let claim = replay.claims[claimID] else { throw VACalleeClaimError.unknownClaim }
        let stale = try Self.classify(claim: claim, observed: observed)
        let required = claim.inventory.callees.map(\.callee)
        var examined = 0, irrelevant = 0, deferred = 0
        var open: [VAAddress64] = [], deferredList: [VAAddress64] = [], contradicting: [VAAddress64] = []
        for callee in required {
            guard let record = claim.outcomes[callee] else { open.append(callee); continue }
            switch record.outcome {
            case .examined:
                examined += 1
                if record.bearing == .contradicts { contradicting.append(callee) }
            case .irrelevant: irrelevant += 1
            case .deferred: deferred += 1; deferredList.append(callee)
            }
        }
        let requiredSet = Set(required)
        let advisory = claim.outcomes.keys.filter { !requiredSet.contains($0) }.count
        let status: VACalleeClaimStatus = stale.kind != nil ? .stale : (open.isEmpty ? .closed : .open)
        let coverage = VACalleeCoverage(required: required.count, examined: examined, irrelevant: irrelevant,
                                        deferred: deferred, open: open.count, advisoryRecorded: advisory,
                                        unresolvedIndirectCallSites: claim.inventory.unresolvedIndirectCallSites,
                                        limitations: claim.inventory.limitations)
        return VACalleeClaimReport(claimID: claimID, revision: claim.revision, binding: claim.binding,
                                   status: status, staleKind: stale.kind, rebindable: stale.rebindable,
                                   projectionEpochMoved: stale.projectionEpochMoved,
                                   addedCallees: stale.addedCallees, removedCallees: stale.removedCallees,
                                   leaf: claim.inventory.isLeaf, closedWithDeferrals: status == .closed && deferred > 0,
                                   coverage: coverage, openCallees: open, deferredCallees: deferredList,
                                   contradictingCallees: contradicting, reboundCount: claim.reboundCount)
    }

    /// Outcomes recorded under superseded revisions, oldest first. Read-only history; never satisfying.
    public func priorOutcomes(claimID: UUID) throws -> [VACalleeOutcomeRecord] {
        guard let claim = replay.claims[claimID] else { throw VACalleeClaimError.unknownClaim }
        return claim.prior.sorted { $0.sequence < $1.sequence }
    }

    /// Every outcome event for one callee across all revisions, in order (the amendment history).
    public func outcomeHistory(claimID: UUID, callee: VAAddress64) -> [VACalleeOutcomeRecord] {
        events.compactMap { event in
            guard event.claimID == claimID, event.kind == .outcomeRecorded, event.callee == callee else { return nil }
            return Replay.record(from: event)
        }
    }

    // MARK: Internals

    private var nextSequence: UInt64 { UInt64(events.count + 1) }

    private mutating func append(_ event: VACalleeClaimEvent) throws {
        guard events.count < VACalleeClaimLimits.maximumEvents else { throw VACalleeClaimError.eventLimit }
        try replay.apply(event, expectedSequence: UInt64(events.count + 1))
        events.append(event)
    }

    /// The stale-classification table. Precedence: another image, then an unresolvable function, then the
    /// generation. An equal generation is current whatever the inventory says.
    fileprivate static func classify(claim: Replay.ClaimState,
                                     observed: VACalleeClaimObservation) throws -> VACalleeStaleClassification {
        let none: [VAAddress64] = []
        if observed.imageOwner != claim.binding.imageOwner {
            return .init(kind: .imageChanged, rebindable: false, projectionEpochMoved: false,
                         addedCallees: none, removedCallees: none)
        }
        guard let inventory = observed.inventory else {
            return .init(kind: .functionGone, rebindable: false, projectionEpochMoved: false,
                         addedCallees: none, removedCallees: none)
        }
        try inventory.validate()
        try vaCheck(inventory.function == claim.binding.function, "observed inventory is for another function")
        if observed.generation == claim.binding.analysisGeneration {
            return .init(kind: nil, rebindable: false, projectionEpochMoved: false, addedCallees: none, removedCallees: none)
        }
        if inventory.inventoryDigest == claim.binding.inventoryDigest {
            return .init(kind: .generationAdvanced, rebindable: true,
                         projectionEpochMoved: observed.projectionEpoch != claim.binding.projectionEpoch,
                         addedCallees: none, removedCallees: none)
        }
        let before = Set(claim.inventory.callees.map(\.callee)), after = Set(inventory.callees.map(\.callee))
        return .init(kind: .inventoryChanged, rebindable: false, projectionEpochMoved: false,
                     addedCallees: after.subtracting(before).sorted(), removedCallees: before.subtracting(after).sorted())
    }

    fileprivate struct Replay: Sendable {
        struct ClaimState: Sendable {
            var revision: Int
            var binding: VACalleeClaimBinding
            var inventory: VACalleeInventory
            var outcomes: [VAAddress64: VACalleeOutcomeRecord] = [:]
            var knownCallees: Set<VAAddress64>
            var prior: [VACalleeOutcomeRecord] = []
            var reboundCount = 0
        }

        var claims: [UUID: ClaimState] = [:]
        var order: [UUID] = []

        static func record(from event: VACalleeClaimEvent) -> VACalleeOutcomeRecord {
            VACalleeOutcomeRecord(callee: event.callee!, outcome: event.outcome!, reason: event.reason!,
                                  bearing: event.bearing, bodyDigest: event.bodyDigest, witness: event.witness,
                                  sequence: event.sequence, revision: event.revision)
        }

        static func known(_ inventory: VACalleeInventory) -> Set<VAAddress64> {
            Set(inventory.callees.map(\.callee)).union(inventory.indirect.map(\.target))
        }

        /// All checks run before any mutation, so a refused event leaves the state untouched.
        mutating func apply(_ event: VACalleeClaimEvent, expectedSequence: UInt64) throws {
            try vaCheck(event.sequence == expectedSequence, "event sequence is duplicated, skipped or out of order")
            try event.validateShape()
            let id = event.claimID
            switch event.kind {
            case .claimOpened:
                guard claims[id] == nil else { throw VACalleeClaimError.duplicateClaim }
                guard claims.count < VACalleeClaimLimits.maximumClaims else { throw VACalleeClaimError.claimLimit }
                let binding = event.binding!, inventory = event.inventory!
                guard !claims.values.contains(where: { $0.binding.sameTarget(as: binding) }) else {
                    throw VACalleeClaimError.duplicateClaim
                }
                claims[id] = ClaimState(revision: 1, binding: binding, inventory: inventory,
                                        knownCallees: Self.known(inventory))
                order.append(id)
            case .outcomeRecorded:
                guard let claim = claims[id] else { throw VACalleeClaimError.unknownClaim }
                try vaCheck(event.revision == claim.revision, "outcome revision does not match the claim")
                guard claim.knownCallees.contains(event.callee!) else {
                    throw VACalleeClaimError.calleeNotInClaim(event.callee!)
                }
                claims[id]?.outcomes[event.callee!] = Self.record(from: event)
            case .claimRebound:
                guard let claim = claims[id] else { throw VACalleeClaimError.unknownClaim }
                let binding = event.binding!
                try vaCheck(event.revision == claim.revision, "rebind revision does not match the claim")
                try vaCheck(binding.sameTarget(as: claim.binding), "rebind may not change the target")
                try vaCheck(binding.inventoryDigest == claim.binding.inventoryDigest, "rebind may not change the inventory digest")
                try vaCheck(event.previousGeneration == claim.binding.analysisGeneration, "rebind previous generation")
                try vaCheck(binding.analysisGeneration != claim.binding.analysisGeneration, "rebind to the same generation")
                for callee in event.invalidatedCallees! {
                    try vaCheck(claim.outcomes[callee]?.outcome == .examined, "only examined callees can be invalidated")
                }
                claims[id]?.binding = binding
                claims[id]?.reboundCount += 1
                for callee in event.invalidatedCallees! { claims[id]?.outcomes[callee] = nil }
            case .claimSuperseded:
                guard let claim = claims[id] else { throw VACalleeClaimError.unknownClaim }
                let binding = event.binding!, inventory = event.inventory!
                try vaCheck(event.revision == claim.revision + 1, "superseded revision must follow the current one")
                try vaCheck(binding.slot >= 0 && binding.function == claim.binding.function,
                            "supersede may not change the function")
                guard !claims.contains(where: { $0.key != id && $0.value.binding.sameTarget(as: binding) }) else {
                    throw VACalleeClaimError.duplicateClaim
                }
                let carried = claim.outcomes.values.sorted { $0.sequence < $1.sequence }
                claims[id] = ClaimState(revision: event.revision, binding: binding, inventory: inventory,
                                        knownCallees: Self.known(inventory), prior: claim.prior + carried)
            }
        }
    }
}
