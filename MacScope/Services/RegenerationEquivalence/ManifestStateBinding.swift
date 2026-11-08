import Foundation

/// Built from the validated captured snapshot, never from a caller's manifest claims.
struct EquivalenceManifestBindings: Sendable {
    struct Function: Sendable {
        let exportUUID: UUID
        let capturedID: String
        let address: UInt64
        let size: UInt64
    }
    let image: RegenerationImageIdentity
    let functions: [Function]
}

enum ManifestStateBinding {
    private struct Extent: Hashable { let address: UInt64; let size: UInt64 }

    /// Shared by every comparison entry point. Schema support does not authorize exclusions.
    static func validate(_ manifest: RegenerationManifest, budget: RegenerationWorkBudget) throws {
        try budget.checkpoint()
        guard manifest.schemaVersion == 1 || manifest.schemaVersion == 2 else {
            throw EquivalenceInputError.unsupportedManifestSchema
        }
        guard manifest.functions.count <= budget.maximumRecords else {
            throw RegenerationWorkBudgetError.recordLimitExceeded
        }
        var remainingBytes = budget.maximumInputBytes
        for record in manifest.functions {
            try budget.checkpoint()
            guard manifest.schemaVersion == 2 || (record.state != .external && record.dependencyId == nil) else {
                throw EquivalenceInputError.invalidManifestDeclaration
            }
            if let dependency = record.dependencyId {
                guard dependency.utf8.count <= remainingBytes else {
                    throw RegenerationWorkBudgetError.inputLimitExceeded
                }
                remainingBytes -= dependency.utf8.count
                guard !dependency.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw EquivalenceInputError.invalidManifestDeclaration
                }
            }
        }
    }


    static func observations(manifest: RegenerationManifest?, image: RegenerationImageIdentity,
                             functions: [FunctionVersionFingerprint], bindings: EquivalenceManifestBindings?,
                             pairing: PairingProjection?, budget: RegenerationWorkBudget) throws -> [FunctionStateObservation] {
        try budget.checkpoint()
        guard let manifest else { return [] }
        try validate(manifest, budget: budget)
        guard manifest.image == image, bindings == nil || bindings?.image == image else {
            throw EquivalenceInputError.manifestIdentityMismatch
        }
        var remaining = budget.maximumRecords
        for count in [manifest.functions.count, functions.count, bindings?.functions.count ?? 0,
                      pairing?.matches.count ?? 0] {
            guard count <= remaining else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            remaining -= count
        }
        func extent(_ record: RegenerationFunctionRecord) -> Extent? {
            let c = record.imageQualifiedAddress
            guard c.imageSlot == image.imageSlot, c.selectedSliceIndex == image.selectedSliceIndex,
                  c.imageSHA256 == image.selectedSliceSHA256,
                  c.address.count == 18, c.address.hasPrefix("0x"),
                  c.endAddressExclusive.count == 18, c.endAddressExclusive.hasPrefix("0x"),
                  let start = UInt64(c.address.dropFirst(2), radix: 16),
                  let end = UInt64(c.endAddressExclusive.dropFirst(2), radix: 16), end >= start else { return nil }
            return Extent(address: start, size: end - start)
        }
        var records: [(RegenerationFunctionRecord, Extent?)] = []
        for record in manifest.functions {
            try budget.checkpoint()
            guard record.imageQualifiedAddress.address.utf8.count <= 18,
                  record.imageQualifiedAddress.endAddressExclusive.utf8.count <= 18 else {
                throw RegenerationWorkBudgetError.inputLimitExceeded
            }
            records.append((record, extent(record)))
        }
        let manifestIDs = Dictionary(grouping: records, by: { $0.0.functionUUID })
        let manifestExtents = Dictionary(grouping: records, by: { $0.1 })
        let capturedExtents = Dictionary(grouping: functions, by: { Extent(address: $0.address, size: $0.size) })
        let capturedIDs = Dictionary(grouping: functions, by: \.id)
        let exports = Dictionary(grouping: bindings?.functions ?? [], by: \.exportUUID)
        let pairs = Dictionary(grouping: pairing?.matches ?? [], by: \.oldID)
        let rebuiltIDs = Dictionary(grouping: pairing?.matches ?? [], by: \.newID)
        return try records.map { record, coordinate in
            try budget.checkpoint()
            var capturedID: String?
            let status: String
            if let coordinate {
                if manifestIDs[record.functionUUID]?.count != 1 || manifestExtents[coordinate]?.count != 1 {
                    status = "ambiguousManifestFunction"
                } else if bindings == nil {
                    status = "exportIdentityBridgeUnavailable"
                } else if let candidates = exports[record.functionUUID], candidates.count == 1,
                          let candidate = candidates.first {
                    let captured = capturedExtents[coordinate] ?? []
                    if candidate.address != coordinate.address || candidate.size != coordinate.size {
                        status = "exportIdentityExtentMismatch"
                    } else if captured.count != 1 || capturedIDs[candidate.capturedID]?.count != 1 {
                        status = "ambiguousOrMissingCapturedFunction"
                    } else if captured.first?.id != candidate.capturedID {
                        status = "capturedIdentityMismatch"
                    } else {
                        capturedID = candidate.capturedID
                        status = "boundToCapturedFunction"
                    }
                } else {
                    status = "unknownOrAmbiguousExportIdentity"
                }
            } else {
                status = "invalidOrMismatchedCoordinate"
            }
            var rebuiltID: String?
            if let capturedID, let matches = pairs[capturedID], matches.count == 1, let match = matches.first,
               match.basis == .symbolName, match.oldAddress == coordinate?.address,
               rebuiltIDs[match.newID]?.count == 1 {
                rebuiltID = match.newID
            }
            return FunctionStateObservation(originalFunctionUUID: record.functionUUID.uuidString.lowercased(),
                originalFunctionID: capturedID, state: record.state.rawValue,
                declaredAddress: record.imageQualifiedAddress.address,
                declaredEndAddressExclusive: record.imageQualifiedAddress.endAddressExclusive,
                bindingStatus: status, rebuiltFunctionID: rebuiltID,
                pairingStatus: rebuiltID == nil ? "unassessedOrUnpaired" : "associatedByUniqueRawSymbol",
                authority: "manifestDeclarationOnly", dependencyId: record.dependencyId, exclusionApplied: false)
        }.sorted {
            if $0.originalFunctionUUID != $1.originalFunctionUUID { return $0.originalFunctionUUID < $1.originalFunctionUUID }
            if $0.declaredAddress != $1.declaredAddress { return $0.declaredAddress < $1.declaredAddress }
            if $0.declaredEndAddressExclusive != $1.declaredEndAddressExclusive { return $0.declaredEndAddressExclusive < $1.declaredEndAddressExclusive }
            return $0.state < $1.state
        }
    }
}
