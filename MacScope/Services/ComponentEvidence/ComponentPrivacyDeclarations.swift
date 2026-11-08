// Original to this lane. Captures PrivacyInfo.xcprivacy. notPresent is recorded only for a typed ENOENT on the
// explicit manifest path after the owning component's resources directory chain was opened successfully.

import Darwin
import Foundation

extension ComponentEvidence {
    enum PrivacyDeclarations {
        static func capture(_ session: ActiveSession, inventoryID: UUID, component: ComponentRecord) throws -> DeclarationObservation {
            guard let locations = CodeUnitDeclarationLocations.locations(for: component.path) else {
                return try unavailable(inventoryID, component, EvidenceIssue(.sourceMismatch, range: .leaf(component.path)))
            }
            let source = locations.privacyPath
            let range = PathRange.leaf(source)
            do {
                if Task.isCancelled { throw EvidenceError.cancelled }
                // Preflight: the resources directory must open, so ENOENT on the manifest is meaningful.
                let directory = try session.ops.openRelative(session.root, locations.resourcePath, directory: true)
                session.ops.close(directory)
                let bytes = try BundleDiscovery.readSmallFile(session, path: source)
                let values = try DeclarationObservation.decode(bytes, source: source, category: .privacy)
                return try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .privacy, state: .present,
                                                  values: values, source: DeclarationSource(path: source, architecture: nil))
            } catch EvidenceError.io(let operation, let code, let failedRange) where code == ENOENT && operation == .openFile && failedRange == range {
                return try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .privacy, state: .notPresent,
                                                  source: DeclarationSource(path: source, architecture: nil))
            } catch let error as EvidenceError {
                return try unavailable(inventoryID, component, EvidenceIssue(error, range: range))
            }
        }

        private static func unavailable(_ inventoryID: UUID, _ component: ComponentRecord, _ issue: EvidenceIssue) throws -> DeclarationObservation {
            try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .privacy, state: .unavailable, issue: issue)
        }
    }
}
