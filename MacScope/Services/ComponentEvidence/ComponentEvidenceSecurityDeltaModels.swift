// Original to this item (AR3, NF01). Immutable value models of the component security delta report.
// Nothing here reads a file, opens a bundle, hashes bytes or encodes a report: there is no Codable, no archive
// and no saved-wire promise. Unknown counts are nil, never zero. Exact identities are never truncated.

import Foundation

enum ComponentEvidenceSecurityDelta {
    // MARK: Closed vocabularies

    /// Fixed traversal and display order is declaration order.
    enum Category: Int, Sendable, Hashable, CaseIterable, Comparable {
        case componentInventory, informationPropertyList, loadCommands, entitlements, privacyManifest, signatureEvidence
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    enum Disposition: String, Sendable, Hashable {
        case observedAddition, observedRemoval, observedChange, unchanged, unresolved, declined
    }

    /// There is no both case: bilateral evidence carries one reference per side.
    enum Side: Int, Sendable, Hashable, Comparable {
        case previous, current
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    /// AR2 present maps to observed, notPresent to absent. Unavailable never maps to absent.
    enum SourceState: String, Sendable, Hashable { case observed, absent, unavailable, unexamined, excluded, unknown }

    enum FindingKind: String, Sendable, Hashable {
        case componentAdded, componentRemoved, xpcAdded, declarationChanged, signatureEvidenceChanged
        case componentMultiCategory, relatedComponents, repeatedDeclaration, coverageIncomplete, evidenceConflict
    }

    /// A short exact label for an unrecognized upstream kind. Bounded; never an error dump.
    struct BoundedLabel: Sendable, Hashable {
        static let maximumBytes = 64
        let text: String
        init(_ text: String) throws {
            guard !text.isEmpty, text.utf8.count <= Self.maximumBytes else { throw ModelError.invalid(.invalidReview) }
            self.text = text
        }
    }

    enum UnderlyingKind: Sendable, Hashable {
        case unavailable, stale, permissionDenied, readFailed, malformed, unsupported, cancelled, deadline, bindingMismatch, budget
        case unrecognized(BoundedLabel)
    }

    /// The reached bound is retained by name; it is never guessed.
    enum Cap: Sendable, Hashable {
        case componentLimit, declarationLimit, sourceRecordLimit, retainedByteLimit, typedDepthLimit, typedNodeLimit
        case decodedByteLimit, observationLimit, findingLimit, evidenceReferenceLimit, limitationLimit, diagnosticLimit
        case textLimit, loaderRowLimit, loaderPathLimit, captureByteLimit, pageByteLimit, registryCapacity
        case upstream(UnderlyingKind)
    }

    enum ReasonCode: Sendable, Hashable {
        case sourceUnavailable, sourceBindingUnverified, numericRepresentationUnspecified, loaderInterpretationUnavailable
        case loaderGroupEvidence, componentCorrespondenceUnaccepted, categoryUnexamined, evidenceConflict
        case sliceCorrespondenceUnresolved, signatureUnexamined, signatureMalformed, signatureBudgetExceeded
        case signatureStatesUnresolved, inventoryExcluded, inventoryIncomplete, scopeUnsearched, staticEvidenceOnly
        case transitionValueUnavailable, unsupportedArchitecture, readFailed, parserCrossCheckDifference
        case xmlDerDisagreement, oneFormUnavailable, unsupportedHashType, codeDirectoryCorrespondenceUnresolved
        case cap(Cap)
        case upstreamUnknown(UnderlyingKind)
    }

    enum RefusalCode: String, Sendable, Hashable {
        case invalidReview, duplicateComponentIdentity, duplicateObservationIdentity, danglingEvidenceReference
        case evidenceBindingMismatch, componentCorrespondenceUnaccepted, sourceStale, invalidOptions
        case previousUnavailable, currentUnavailable, providerUnavailable, ambiguousSelection, deadlineExceeded, cancelled
        case staleCursor, malformedInput, outOfBounds, asyncTransportRequired, pageByteLimit, registryCapacity
    }

    /// Construction of a malformed graph throws; resource exhaustion is converted to PARTIAL by the caller.
    enum ModelError: Error, Sendable, Hashable { case invalid(RefusalCode) }

    // MARK: Exact text

    /// Valid UTF-8 bytes. Equality and order use the bytes, never Swift canonical String equality.
    struct ExactKey: Sendable, Hashable, Comparable {
        let utf8: Data
        init(utf8 data: Data) throws {
            guard String(data: data, encoding: .utf8) != nil else { throw ModelError.invalid(.invalidReview) }
            utf8 = data
        }
        /// Retains the supplied text's UTF-8 only; no claim that lost source distinctions are recovered.
        init(text: String) { utf8 = Data(text.utf8) }
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.utf8.lexicographicallyPrecedes(rhs.utf8) }
        var byteCount: Int { utf8.count }
    }

    struct Reason: Sendable, Hashable {
        static let maximumDiagnosticBytes = 256
        let code: ReasonCode
        let diagnostic: String
        /// The diagnostic is bounded and is never parsed back into a state.
        init(code: ReasonCode, diagnostic: String) throws {
            guard diagnostic.utf8.count <= Self.maximumDiagnosticBytes else { throw ModelError.invalid(.invalidReview) }
            self.code = code; self.diagnostic = diagnostic
        }
    }

    // MARK: Identities

    struct ComponentIdentity: Sendable, Hashable {
        let side: Side
        let inventoryID: UUID
        let componentID: UUID
        let relativePath: ExactKey
        let kind: String
        let parentID: UUID?
        init(side: Side, inventoryID: UUID, componentID: UUID, relativePath: ExactKey, kind: String, parentID: UUID?) throws {
            guard relativePath.byteCount > 0, parentID != componentID else { throw ModelError.invalid(.invalidReview) }
            self.side = side; self.inventoryID = inventoryID; self.componentID = componentID
            self.relativePath = relativePath; self.kind = kind; self.parentID = parentID
        }
    }

    /// Numeric facts of one slice. No masking. Digest unknown is nil, never empty bytes.
    struct SliceIdentity: Sendable, Hashable {
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let headerMagic: UInt32
        let index: Int
        let offset: UInt64
        let size: UInt64
        let recordedSHA256: Data?
        init(cpuType: UInt32, cpuSubtype: UInt32, headerMagic: UInt32, index: Int, offset: UInt64, size: UInt64,
             recordedSHA256: Data?) throws {
            guard index >= 0, size <= UInt64.max - offset, recordedSHA256 == nil || recordedSHA256?.count == 32 else {
                throw ModelError.invalid(.invalidReview)
            }
            self.cpuType = cpuType; self.cpuSubtype = cpuSubtype; self.headerMagic = headerMagic
            self.index = index; self.offset = offset; self.size = size; self.recordedSHA256 = recordedSHA256
        }
        /// Index, offset, size and digest are evidence, never pairing fields.
        var pairingKey: PairingKey { PairingKey(cpuType: cpuType, cpuSubtype: cpuSubtype, headerMagic: headerMagic) }
    }

    struct PairingKey: Sendable, Hashable, Comparable {
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let headerMagic: UInt32
        static func < (lhs: Self, rhs: Self) -> Bool {
            (lhs.cpuType, lhs.cpuSubtype, lhs.headerMagic) < (rhs.cpuType, rhs.cpuSubtype, rhs.headerMagic)
        }
    }

    /// The architecture label is descriptive and is never admission or pairing authority.
    struct ReviewIdentity: Sendable, Hashable {
        let previousInventoryID: UUID
        let currentInventoryID: UUID
        let architecture: String
        let evidenceBasisID: UUID
    }

    struct RowID: Sendable, Hashable, Comparable {
        let reportID: UUID
        let ordinal: Int
        init(reportID: UUID, ordinal: Int) throws {
            guard ordinal >= 0 else { throw ModelError.invalid(.invalidReview) }
            self.reportID = reportID; self.ordinal = ordinal
        }
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.ordinal < rhs.ordinal }
    }

    /// A distinct domain from RowID so a finding is never mistaken for an observation.
    struct FindingID: Sendable, Hashable, Comparable {
        let reportID: UUID
        let ordinal: Int
        init(reportID: UUID, ordinal: Int) throws {
            guard ordinal >= 0 else { throw ModelError.invalid(.invalidReview) }
            self.reportID = reportID; self.ordinal = ordinal
        }
        static func < (lhs: Self, rhs: Self) -> Bool { lhs.ordinal < rhs.ordinal }
    }

    struct EvidenceReference: Sendable, Hashable {
        let side: Side
        let inventoryID: UUID
        /// Nil is a scope reference. No field gives filesystem authority.
        let componentID: UUID?
        let category: Category
        let relativeSource: ExactKey
        let architecture: String?
        let evidenceKey: ExactKey?
        let slice: SliceIdentity?
        init(side: Side, inventoryID: UUID, componentID: UUID?, category: Category, relativeSource: ExactKey,
             architecture: String?, evidenceKey: ExactKey?, slice: SliceIdentity?) throws {
            self.side = side; self.inventoryID = inventoryID; self.componentID = componentID; self.category = category
            self.relativeSource = relativeSource; self.architecture = architecture; self.evidenceKey = evidenceKey
            self.slice = slice
        }
    }

    // MARK: Bounded ranges and omissions

    /// Half-open ranges in explicitly named domains. An unknown range is not invented.
    enum BoundedRange: Sendable, Hashable {
        case notStarted
        case records(side: Side?, componentPath: ExactKey?, slice: PairingKey?, list: String, start: Int, endExclusive: Int)
        case bytes(side: Side, componentPath: ExactKey?, slice: PairingKey?, start: UInt64, endExclusive: UInt64)

        static func checkedRecords(side: Side?, componentPath: ExactKey?, slice: PairingKey?, list: String, start: Int,
                                   endExclusive: Int) throws -> BoundedRange {
            guard start >= 0, start <= endExclusive else { throw ModelError.invalid(.invalidReview) }
            return .records(side: side, componentPath: componentPath, slice: slice, list: list, start: start, endExclusive: endExclusive)
        }

        static func checkedBytes(side: Side, componentPath: ExactKey?, slice: PairingKey?, start: UInt64,
                                 endExclusive: UInt64) throws -> BoundedRange {
            guard start <= endExclusive else { throw ModelError.invalid(.invalidReview) }
            return .bytes(side: side, componentPath: componentPath, slice: slice, start: start, endExclusive: endExclusive)
        }
    }

    /// Counts from different domains are never summed as observation omissions.
    enum OmissionDomain: String, Sendable, Hashable {
        case observations, findings, slices, components, declarations, entitlementForms, codeDirectories, sourceRecords, renderedDetails
    }

    struct Omission: Sendable, Hashable {
        let count: Int?
        let countIsExact: Bool
        let detailListComplete: Bool
        let reason: Reason
        let domain: OmissionDomain
        let cap: Cap?
        let boundedRange: BoundedRange?
        let remainderUnknown: Bool
        let lowerBound: Int?

        /// A nil count is nonexact. An inexact positive count belongs in `lowerBound`, never in `count`.
        init(count: Int?, countIsExact: Bool, detailListComplete: Bool, reason: Reason, domain: OmissionDomain, cap: Cap?,
             boundedRange: BoundedRange?, remainderUnknown: Bool, lowerBound: Int?) throws {
            if let count { guard count >= 0, countIsExact else { throw ModelError.invalid(.invalidReview) } }
            else { guard !countIsExact else { throw ModelError.invalid(.invalidReview) } }
            if let lowerBound { guard lowerBound >= 0, count == nil || lowerBound <= count! else { throw ModelError.invalid(.invalidReview) } }
            self.count = count; self.countIsExact = countIsExact; self.detailListComplete = detailListComplete
            self.reason = reason; self.domain = domain; self.cap = cap; self.boundedRange = boundedRange
            self.remainderUnknown = remainderUnknown; self.lowerBound = lowerBound
        }
    }

    struct PartialDetail: Sendable, Hashable {
        let cap: Cap?
        let reason: Reason
        let side: Side?
        let knownMismatchIDs: [RowID]
        let boundedRange: BoundedRange?
        let omissionCount: Int?
        let remainderUnknown: Bool
        init(cap: Cap?, reason: Reason, side: Side?, knownMismatchIDs: [RowID], boundedRange: BoundedRange?,
             omissionCount: Int?, remainderUnknown: Bool) throws {
            if let omissionCount { guard omissionCount >= 0 else { throw ModelError.invalid(.invalidReview) } }
            guard Set(knownMismatchIDs).count == knownMismatchIDs.count else { throw ModelError.invalid(.duplicateObservationIdentity) }
            self.cap = cap; self.reason = reason; self.side = side; self.knownMismatchIDs = knownMismatchIDs
            self.boundedRange = boundedRange; self.omissionCount = omissionCount; self.remainderUnknown = remainderUnknown
        }
    }

    // MARK: Denominators and coverage

    /// Accounted classifications are disjoint; an unknown total is nil.
    struct OpportunityCounts: Sendable, Hashable {
        let accounted: Int
        let compared: Int
        let provenAbsent: Int
        let symmetricUnexamined: Int
        let unresolved: Int
        let excluded: Int
        let total: Int?
        init(accounted: Int, compared: Int, provenAbsent: Int, symmetricUnexamined: Int, unresolved: Int, excluded: Int,
             total: Int?) throws {
            let parts = [compared, provenAbsent, symmetricUnexamined, unresolved, excluded]
            guard parts.allSatisfy({ $0 >= 0 }), accounted == parts.reduce(0, +), total == nil || total! >= accounted else {
                throw ModelError.invalid(.invalidReview)
            }
            self.accounted = accounted; self.compared = compared; self.provenAbsent = provenAbsent
            self.symmetricUnexamined = symmetricUnexamined; self.unresolved = unresolved; self.excluded = excluded; self.total = total
        }
    }

    /// Slices have a ledger separate from the category ledger.
    struct SliceCounts: Sendable, Hashable {
        let observedKeys: Int
        let uniquelyPaired: Int
        let comparedSupported: Int
        let unexaminedNotCompared: Int
        let unmatched: Int
        let ambiguous: Int
        let total: Int?
        init(observedKeys: Int, uniquelyPaired: Int, comparedSupported: Int, unexaminedNotCompared: Int, unmatched: Int,
             ambiguous: Int, total: Int?) throws {
            let all = [observedKeys, uniquelyPaired, comparedSupported, unexaminedNotCompared, unmatched, ambiguous]
            guard all.allSatisfy({ $0 >= 0 }), comparedSupported + unexaminedNotCompared <= uniquelyPaired,
                  uniquelyPaired + unmatched + ambiguous <= observedKeys, total == nil || total! >= observedKeys else {
                throw ModelError.invalid(.invalidReview)
            }
            self.observedKeys = observedKeys; self.uniquelyPaired = uniquelyPaired; self.comparedSupported = comparedSupported
            self.unexaminedNotCompared = unexaminedNotCompared; self.unmatched = unmatched; self.ambiguous = ambiguous
            self.total = total
        }
    }

    struct Denominators: Sendable, Hashable {
        let categories: OpportunityCounts
        let slices: SliceCounts
        /// The uncapped observation population when known, never the page total.
        let populationTotal: Int?
        init(categories: OpportunityCounts, slices: SliceCounts, populationTotal: Int?) throws {
            if let populationTotal { guard populationTotal >= 0 else { throw ModelError.invalid(.invalidReview) } }
            self.categories = categories; self.slices = slices; self.populationTotal = populationTotal
        }
    }

    enum ScopeState: String, Sendable, Hashable { case completeWithinScope, partial, excluded, unknown }
    enum Completion: String, Sendable, Hashable { case complete, partial }

    /// No hidden mutable ledger and no PASS field: evidence only.
    struct Coverage: Sendable, Hashable {
        let previousScope: ScopeState
        let currentScope: ScopeState
        let previousLocations: [ExactKey]
        let currentLocations: [ExactKey]
        let previousExclusions: [Reason]
        let currentExclusions: [Reason]
        let previousIssues: [Reason]
        let currentIssues: [Reason]
        let limitations: [Reason]
        let omissions: [Omission]
        let denominators: Denominators
        let status: Completion
        let partialDetails: [PartialDetail]

        init(previousScope: ScopeState, currentScope: ScopeState, previousLocations: [ExactKey], currentLocations: [ExactKey],
             previousExclusions: [Reason], currentExclusions: [Reason], previousIssues: [Reason], currentIssues: [Reason],
             limitations: [Reason], omissions: [Omission], denominators: Denominators, status: Completion,
             partialDetails: [PartialDetail]) throws {
            // A complete report cannot carry a cap, an omission or a partial scope.
            if status == .complete {
                guard omissions.isEmpty, partialDetails.isEmpty, previousScope == .completeWithinScope,
                      currentScope == .completeWithinScope else { throw ModelError.invalid(.invalidReview) }
            }
            self.previousScope = previousScope; self.currentScope = currentScope
            self.previousLocations = previousLocations; self.currentLocations = currentLocations
            self.previousExclusions = previousExclusions; self.currentExclusions = currentExclusions
            self.previousIssues = previousIssues; self.currentIssues = currentIssues; self.limitations = limitations
            self.omissions = omissions; self.denominators = denominators; self.status = status; self.partialDetails = partialDetails
        }
    }

    /// Only reducing a limit is allowed. No option disables a category or enables IO.
    struct Options: Sendable, Hashable {
        static let observationCeiling = 8192
        static let findingCeiling = 2048
        let maximumObservations: Int
        let maximumFindings: Int
        init(maximumObservations: Int = Options.observationCeiling, maximumFindings: Int = Options.findingCeiling) throws {
            guard (1...Self.observationCeiling).contains(maximumObservations),
                  (1...Self.findingCeiling).contains(maximumFindings) else { throw ModelError.invalid(.invalidOptions) }
            self.maximumObservations = maximumObservations; self.maximumFindings = maximumFindings
        }
    }

    // MARK: Observations, findings, report

    struct Observation: Sendable, Hashable {
        static let maximumReferences = 32
        static let maximumLimitations = 32
        let id: RowID
        let category: Category
        let componentPath: ExactKey
        let subject: ExactKey
        let disposition: Disposition
        let previousState: SourceState
        let currentState: SourceState
        let previousValue: Value?
        let currentValue: Value?
        let evidence: [EvidenceReference]
        let limitations: [Reason]

        /// Nil endpoints are not empty values. A value requires an observed state. Unresolved requires named limitations.
        init(id: RowID, category: Category, componentPath: ExactKey, subject: ExactKey, disposition: Disposition,
             previousState: SourceState, currentState: SourceState, previousValue: Value?, currentValue: Value?,
             evidence: [EvidenceReference], limitations: [Reason]) throws {
            guard previousValue == nil || previousState == .observed, currentValue == nil || currentState == .observed,
                  evidence.count <= Self.maximumReferences, limitations.count <= Self.maximumLimitations,
                  disposition != .unresolved || !limitations.isEmpty else { throw ModelError.invalid(.invalidReview) }
            self.id = id; self.category = category; self.componentPath = componentPath; self.subject = subject
            self.disposition = disposition; self.previousState = previousState; self.currentState = currentState
            self.previousValue = previousValue; self.currentValue = currentValue; self.evidence = evidence
            self.limitations = limitations
        }

        /// Everything except the report-local identity: two observations with the same key are one input error.
        fileprivate var semanticKey: SemanticKey {
            SemanticKey(category: category, componentPath: componentPath, subject: subject, disposition: disposition,
                        previousState: previousState, currentState: currentState, previousValue: previousValue,
                        currentValue: currentValue, evidence: evidence)
        }

        fileprivate struct SemanticKey: Hashable {
            let category: Category
            let componentPath: ExactKey
            let subject: ExactKey
            let disposition: Disposition
            let previousState: SourceState
            let currentState: SourceState
            let previousValue: Value?
            let currentValue: Value?
            let evidence: [EvidenceReference]
        }
    }

    /// A finding is whole or absent: it references retained rows only.
    struct Finding: Sendable, Hashable {
        let id: FindingID
        let kind: FindingKind
        let disposition: Disposition
        let title: String
        let explanation: String
        let observationIDs: [RowID]
        let evidence: [EvidenceReference]
        let limitations: [Reason]
        init(id: FindingID, kind: FindingKind, disposition: Disposition, title: String, explanation: String,
             observationIDs: [RowID], evidence: [EvidenceReference], limitations: [Reason]) throws {
            guard !observationIDs.isEmpty, Set(observationIDs).count == observationIDs.count,
                  evidence.count <= Observation.maximumReferences, limitations.count <= Observation.maximumLimitations else {
                throw ModelError.invalid(.invalidReview)
            }
            self.id = id; self.kind = kind; self.disposition = disposition; self.title = title
            self.explanation = explanation; self.observationIDs = observationIDs; self.evidence = evidence
            self.limitations = limitations
        }
    }

    /// The report identity is the evidence basis ID. Validation closes every reference before publication.
    struct Report: Sendable, Hashable {
        let identity: ReviewIdentity
        let options: Options
        let observations: [Observation]
        let findings: [Finding]
        let coverage: Coverage
        var reportID: UUID { identity.evidenceBasisID }

        init(identity: ReviewIdentity, options: Options, observations: [Observation], findings: [Finding],
             coverage: Coverage) throws {
            guard observations.count <= options.maximumObservations, findings.count <= options.maximumFindings else {
                throw ModelError.invalid(.invalidOptions)
            }
            let reportID = identity.evidenceBasisID
            for (position, row) in observations.enumerated() {
                guard row.id.reportID == reportID, row.id.ordinal == position else { throw ModelError.invalid(.duplicateObservationIdentity) }
            }
            guard Set(observations.map(\.semanticKey)).count == observations.count else {
                throw ModelError.invalid(.duplicateObservationIdentity)
            }
            let retained = Set(observations.map(\.id))
            for (position, finding) in findings.enumerated() {
                guard finding.id.reportID == reportID, finding.id.ordinal == position else {
                    throw ModelError.invalid(.duplicateObservationIdentity)
                }
                guard finding.observationIDs.allSatisfy(retained.contains) else { throw ModelError.invalid(.danglingEvidenceReference) }
            }
            for detail in coverage.partialDetails where !detail.knownMismatchIDs.allSatisfy(retained.contains) {
                throw ModelError.invalid(.danglingEvidenceReference)
            }
            self.identity = identity; self.options = options; self.observations = observations
            self.findings = findings; self.coverage = coverage
        }
    }

    // MARK: Refusals and outcomes

    struct ReadSideFailure: Sendable, Hashable {
        let side: Side
        let code: RefusalCode
        let underlyingKind: UnderlyingKind?
    }

    struct Refusal: Sendable, Hashable, Error {
        let code: RefusalCode
        let side: Side?
        let underlyingKind: UnderlyingKind?
        let sideFailures: [ReadSideFailure]
        /// Side failures are previous then current, unique per side.
        init(code: RefusalCode, side: Side? = nil, underlyingKind: UnderlyingKind? = nil,
             sideFailures: [ReadSideFailure] = []) throws {
            let sides = sideFailures.map(\.side)
            guard Set(sides).count == sides.count, sides == sides.sorted() else { throw ModelError.invalid(.invalidReview) }
            self.code = code; self.side = side; self.underlyingKind = underlyingKind; self.sideFailures = sideFailures
        }
    }

    /// Cancellation and deadline throw and publish no report.
    enum Outcome: Sendable, Hashable {
        case complete(Report)
        case partial(Report)
        case refused(Refusal)
    }
}
