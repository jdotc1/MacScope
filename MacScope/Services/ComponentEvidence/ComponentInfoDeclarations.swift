// Original to this lane. Captures a component's Info.plist declarations as an observation: present or unavailable
// only. An Info.plist that cannot be read is never reported as absent.

import Foundation

extension ComponentEvidence {
    enum InfoDeclarations {
        static func capture(_ session: ActiveSession, inventoryID: UUID, component: ComponentRecord) throws -> DeclarationObservation {
            guard let locations = CodeUnitDeclarationLocations.locations(for: component.path) else {
                return try unavailable(inventoryID, component, EvidenceIssue(.sourceMismatch, range: .leaf(component.path)))
            }
            let source = locations.infoPath
            do {
                if Task.isCancelled { throw EvidenceError.cancelled }
                let bytes = try BundleDiscovery.readSmallFile(session, path: source)
                let values = try DeclarationObservation.decode(bytes, source: source, category: .info)
                return try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .info, state: .present,
                                                  values: values, source: DeclarationSource(path: source, architecture: nil))
            } catch let error as EvidenceError {
                return try unavailable(inventoryID, component, EvidenceIssue(error, range: .leaf(source)))
            }
        }

        private static func unavailable(_ inventoryID: UUID, _ component: ComponentRecord, _ issue: EvidenceIssue) throws -> DeclarationObservation {
            try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .info, state: .unavailable, issue: issue)
        }
    }
}
