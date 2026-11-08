// Component declaration observations and their differences. Original to this lane; the entitlement decoding path
// reuses the existing FoundationEntitlementDecoder and EntitlementComparison unchanged.

import Foundation

extension ComponentEvidence {
    enum DeclarationCategory: String, Sendable, Hashable, CaseIterable { case info, loadCommands, privacy }
    enum DeclarationState: String, Sendable, Hashable { case present, notPresent, unavailable }

    static let maximumObservations = 384
    static let decodeLimits = DecodeLimits(maxDepth: 32, maxNodes: 10_000, maxBytes: 65_536)

    /// Where a declaration was read from. Validated against the owning component at review time.
    struct DeclarationSource: Sendable, Equatable {
        let path: RelativePath
        let architecture: ExactUTF8Key?
    }

    /// One captured fact. Three-valued: unavailable is never absent or empty.
    struct DeclarationObservation: Sendable, Equatable {
        let inventoryID: UUID
        let componentID: UUID
        let category: DeclarationCategory
        let architecture: ExactUTF8Key?
        let state: DeclarationState
        let values: EntitlementDictionary?
        let source: DeclarationSource?
        let issue: EvidenceIssue?

        init(inventoryID: UUID, componentID: UUID, category: DeclarationCategory, architecture: ExactUTF8Key? = nil,
             state: DeclarationState, values: EntitlementDictionary? = nil, source: DeclarationSource? = nil,
             issue: EvidenceIssue? = nil) throws {
            switch category {
            case .loadCommands:
                guard let architecture, !architecture.bytes.isEmpty, architecture.bytes.count <= 255 else {
                    throw EvidenceError.invalidObservation(.emptyArchitecture)
                }
            case .info, .privacy:
                guard architecture == nil else { throw EvidenceError.invalidObservation(.wrongArchitectureField) }
            }
            switch state {
            case .present:
                guard values != nil, source != nil, issue == nil else { throw EvidenceError.invalidObservation(.badStatePayload) }
            case .notPresent:
                guard category == .privacy else { throw EvidenceError.invalidObservation(.notPresentNotAllowed) }
                guard values == nil, source != nil, issue == nil else { throw EvidenceError.invalidObservation(.badStatePayload) }
            case .unavailable:
                guard values == nil, issue != nil else {
                    throw EvidenceError.invalidObservation(issue == nil ? .missingTypedReason : .badStatePayload)
                }
            }
            self.inventoryID = inventoryID; self.componentID = componentID; self.category = category
            self.architecture = architecture; self.state = state; self.values = values; self.source = source; self.issue = issue
        }

        /// Decodes a property-list dictionary payload through the bounded existing decoder.
        static func decode(_ bytes: [UInt8], source: RelativePath, category: DeclarationCategory) throws -> EntitlementDictionary {
            let range = PathRange.leaf(source)
            guard bytes.count <= BundleDiscovery.maximumPlistBytes else { throw EvidenceError.malformedMetadata(category, range, .oversize) }
            var format = PropertyListSerialization.PropertyListFormat.openStep
            guard let object = try? PropertyListSerialization.propertyList(from: Data(bytes), format: &format), format != .openStep else {
                throw EvidenceError.malformedMetadata(category, range, .badPlist)
            }
            guard let dictionary = object as? NSDictionary else { throw EvidenceError.malformedMetadata(category, range, .notDictionary) }
            do { return try FoundationEntitlementDecoder(limits: decodeLimits).decode(dictionary) }
            catch { throw EvidenceError.malformedMetadata(category, range, .badPlist) }
        }

        var key: String { "\(componentID.uuidString)|\(category.rawValue)|\(architecture?.display ?? "")" }
    }

    /// Observation set for one inventory. Construction proves every observation belongs and its source matches.
    struct ComponentReview: Sendable {
        let inventory: ComponentInventory
        let observations: [DeclarationObservation]

        init(inventory: ComponentInventory, observations: [DeclarationObservation]) throws {
            guard observations.count <= maximumObservations else { throw EvidenceError.invalidObservation(.tooManyObservations) }
            var seen = Set<String>()
            for observation in observations {
                guard observation.inventoryID == inventory.id else { throw EvidenceError.invalidObservation(.inventoryMismatch) }
                guard let component = inventory.component(observation.componentID) else {
                    throw EvidenceError.invalidObservation(.unknownComponentRecord)
                }
                guard seen.insert(observation.key).inserted else { throw EvidenceError.invalidObservation(.duplicateObservation) }
                if observation.category == .loadCommands, let architecture = observation.architecture,
                   !component.architectures.contains(architecture) {
                    throw EvidenceError.invalidObservation(.architectureNotEnumerated)
                }
                if let source = observation.source {
                    guard let locations = CodeUnitDeclarationLocations.locations(for: component.path) else {
                        throw EvidenceError.sourceMismatch
                    }
                    let expected: RelativePath
                    switch observation.category {
                    case .info: expected = locations.infoPath
                    case .loadCommands: expected = component.path
                    case .privacy: expected = locations.privacyPath
                    }
                    guard source.path == expected, source.architecture == observation.architecture else {
                        throw EvidenceError.sourceMismatch
                    }
                }
            }
            self.inventory = inventory
            self.observations = observations
        }

        func observation(component: UUID, category: DeclarationCategory, architecture: ExactUTF8Key? = nil) -> DeclarationObservation? {
            observations.first { $0.componentID == component && $0.category == category && $0.architecture == architecture }
        }
    }

    /// Nine-pair matrix: present/present compared, present/absent and absent/present transitions, absent/absent,
    /// and anything involving unavailable stays unavailable.
    struct DeclarationDifference: Sendable {
        enum Kind: String, Sendable { case comparedPresent, becameAbsent, becamePresent, bothAbsent, unavailable }
        let kind: Kind
        let category: DeclarationCategory
        let architecture: ExactUTF8Key?
        let previous: DeclarationObservation
        let current: DeclarationObservation
        let rows: [EntitlementChange]?

        init(previous: DeclarationObservation, current: DeclarationObservation) throws {
            guard previous.category == current.category else { throw EvidenceError.invalidObservation(.componentMismatch) }
            guard previous.architecture == current.architecture else { throw EvidenceError.architectureMismatch }
            let rows: [EntitlementChange]?
            switch (previous.state, current.state) {
            case (.present, .present):
                kind = .comparedPresent
                rows = EntitlementComparison(previous: previous.values ?? EntitlementDictionary(),
                                             current: current.values ?? EntitlementDictionary()).rows
            case (.present, .notPresent): kind = .becameAbsent; rows = nil
            case (.notPresent, .present): kind = .becamePresent; rows = nil
            case (.notPresent, .notPresent): kind = .bothAbsent; rows = nil
            default: kind = .unavailable; rows = nil
            }
            self.rows = rows
            self.category = previous.category; self.architecture = previous.architecture
            self.previous = previous; self.current = current
        }
    }

    /// Differences for one matched component pair across everything both sides observed.
    struct ComponentComparison: Sendable {
        let match: ComponentMatch
        let differences: [DeclarationDifference]

        init(previous: ComponentReview, current: ComponentReview, match: ComponentMatch) throws {
            guard match.status == .sameLocation, let before = match.previousID, let after = match.currentID,
                  previous.inventory.component(before) != nil, current.inventory.component(after) != nil else {
                throw EvidenceError.unknownMatch
            }
            var result: [DeclarationDifference] = []
            for old in previous.observations where old.componentID == before {
                guard let new = current.observation(component: after, category: old.category, architecture: old.architecture) else { continue }
                result.append(try DeclarationDifference(previous: old, current: new))
            }
            self.match = match
            self.differences = result.sorted { ($0.category.rawValue, $0.architecture?.display ?? "") < ($1.category.rawValue, $1.architecture?.display ?? "") }
        }
    }
}
