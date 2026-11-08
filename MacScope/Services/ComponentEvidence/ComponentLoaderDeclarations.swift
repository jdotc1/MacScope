// Original to this lane (payload shape follows the donor's fixed load-declaration field names).
// Builds the load-command observation of one requested architecture directly as a dictionary value with the fixed
// field names. A present image with zero load commands stays present; read failures stay unavailable.

import Foundation

extension ComponentEvidence {
    enum LoaderDeclarations {
        static let maximumPayloadBytes = 65_536

        static func capture(_ session: ActiveSession, inventoryID: UUID, component: ComponentRecord, architecture: ExactUTF8Key,
                            provenance: BundleImageProvenance?, ledger: inout ReadLedger) throws -> DeclarationObservation {
            let range = PathRange.leaf(component.path)
            func unavailable(_ error: EvidenceError) throws -> DeclarationObservation {
                try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .loadCommands,
                                           architecture: architecture, state: .unavailable, issue: EvidenceIssue(error, range: range))
            }
            guard component.architectures.contains(architecture) else { return try unavailable(.architectureMismatch) }
            guard !component.isDeclarationOnly else { return try unavailable(.malformedMetadata(.loadCommands, range, .truncated)) }
            let ops = session.ops
            do {
                if let provenance { try CodeUnitPreflight.revalidate(provenance, session: session) }
                let handle = try ops.openRelative(session.root, component.path, directory: false)
                defer { ops.close(handle) }
                let before = try ops.stat(handle, range)
                let result = ComponentMetadataReader(captureLoadCommands: true).read(
                    size: UInt64(max(0, before.st_size)), range: range, ledger: &ledger) { offset, count in
                    try ops.read(handle, offset: offset, count: count, range)
                }
                if let failure = result.failure { return try unavailable(failure) }
                guard DescriptorOps.same(before, try ops.stat(handle, range)) else { return try unavailable(.changedInput(range)) }
                guard let slice = result.slices.first(where: { $0.architecture == architecture }) else {
                    return try unavailable(.architectureMismatch)
                }
                var rows: [EntitlementValue] = []
                var bytes = 0
                for declaration in slice.loadDeclarations {
                    var fields: [EntitlementEntry] = [
                        EntitlementEntry(key: "architecture", value: .string(declaration.architecture.display)),
                        EntitlementEntry(key: "command", value: .string(declaration.command.rawValue)),
                        EntitlementEntry(key: "path", value: .string(declaration.path.display)),
                    ]
                    if let version = declaration.currentVersion { fields.append(.init(key: "currentVersion", value: .string(version))) }
                    if let version = declaration.compatibilityVersion { fields.append(.init(key: "compatibilityVersion", value: .string(version))) }
                    if let flags = declaration.useFlags { fields.append(.init(key: "useFlags", value: .unsignedInteger(UInt64(flags)))) }
                    bytes += fields.reduce(0) { $0 + $1.key.utf8.count + 16 } + declaration.path.bytes.count
                    guard bytes <= maximumPayloadBytes else { return try unavailable(.budgetExceeded(.payloadBytes, range)) }
                    rows.append(.dictionary(try EntitlementDictionary(entries: fields)))
                }
                let payload = try EntitlementDictionary(entries: [EntitlementEntry(key: "commands", value: .array(rows))])
                return try DeclarationObservation(inventoryID: inventoryID, componentID: component.id, category: .loadCommands,
                    architecture: architecture, state: .present, values: payload,
                    source: DeclarationSource(path: component.path, architecture: architecture))
            } catch let error as EvidenceError {
                return try unavailable(error)
            } catch {
                return try unavailable(.malformedMetadata(.loadCommands, range, .badPlist))
            }
        }
    }
}
