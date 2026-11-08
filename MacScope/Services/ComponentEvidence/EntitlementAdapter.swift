// Original to this lane. Adapts component declaration observations onto the existing entitlement comparison model
// (ExactDeclaredEntitlements, EntitlementComparison) without changing either.

import Foundation

extension ComponentEvidence {
    /// Bounded, nonempty architecture key requested for a comparison.
    struct RequestedArchitecture: Sendable, Hashable {
        let key: ExactUTF8Key
        init(_ key: ExactUTF8Key) throws {
            guard !key.bytes.isEmpty, key.bytes.count <= 255 else { throw EvidenceError.invalidObservation(.emptyArchitecture) }
            self.key = key
        }
    }

    struct ComponentEntitlementSnapshot: Sendable, Equatable {
        let inventoryID: UUID
        let componentID: UUID
        let category: DeclarationCategory
        let architecture: ExactUTF8Key?
        let declarations: ExactDeclaredEntitlements
        let source: DeclarationSource?

        /// State coherence is validated: present carries values, notPresent and unavailable carry none.
        init(_ observation: DeclarationObservation) throws {
            let declarations: ExactDeclaredEntitlements
            switch observation.state {
            case .present:
                guard let values = observation.values else { throw EvidenceError.invalidObservation(.badStatePayload) }
                declarations = ExactDeclaredEntitlements(state: .dictionaryPresent, values: values, reason: nil, format: "plist")
            case .notPresent:
                guard observation.values == nil else { throw EvidenceError.invalidObservation(.badStatePayload) }
                declarations = ExactDeclaredEntitlements(state: .notPresent, values: nil, reason: nil, format: nil)
            case .unavailable:
                guard observation.values == nil else { throw EvidenceError.invalidObservation(.badStatePayload) }
                declarations = ExactDeclaredEntitlements(state: .unavailable, values: nil,
                                                         reason: observation.issue?.kind.rawValue, format: nil)
            }
            inventoryID = observation.inventoryID; componentID = observation.componentID; category = observation.category
            architecture = observation.architecture; self.declarations = declarations; source = observation.source
        }
    }

    struct ComponentEntitlementComparisonResult {
        let previous: ComponentEntitlementSnapshot
        let current: ComponentEntitlementSnapshot
        /// Nil whenever either side is unavailable; a notPresent side compares as an empty set only against present.
        let comparison: EntitlementComparison?

        init(previous: ComponentEntitlementSnapshot, current: ComponentEntitlementSnapshot) throws {
            guard previous.category == current.category else { throw EvidenceError.invalidObservation(.componentMismatch) }
            guard previous.architecture == current.architecture else { throw EvidenceError.architectureMismatch }
            self.previous = previous; self.current = current
            let old = previous.declarations, new = current.declarations
            if old.state == .unavailable || new.state == .unavailable {
                comparison = nil
            } else {
                comparison = EntitlementComparison(previous: old.values ?? EntitlementDictionary(),
                                                   current: new.values ?? EntitlementDictionary())
            }
        }
    }
}
