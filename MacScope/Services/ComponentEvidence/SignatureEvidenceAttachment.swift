// Original to this item (AR2). An immutable side table of signature evidence keyed by inventory, component path
// bytes and numeric slice key. It stores no live authority, and no registration line is added to ComponentRecord.
// A display string is never a join key: same-looking slices in different components or inventories do not join.

import Foundation

extension ComponentEvidence {
    struct SignatureEvidenceKey: Sendable, Hashable {
        let inventoryID: UUID
        /// The byte-valued relative path of the component.
        let componentID: RelativePath
        let slice: SignatureSliceKey
    }

    /// One component whose capture threw; nothing partial was published for it.
    struct SignatureCaptureFailure: Sendable, Hashable {
        let componentID: RelativePath
        let error: SignatureCaptureError
    }

    struct SignatureEvidenceAttachment: Sendable {
        let inventoryID: UUID
        private let containers: [RelativePath: SignatureEvidence]
        let failures: [SignatureCaptureFailure]

        init(inventoryID: UUID, entries: [(componentID: RelativePath, evidence: SignatureEvidence)],
             failures: [SignatureCaptureFailure] = []) throws {
            var table: [RelativePath: SignatureEvidence] = [:]
            for entry in entries {
                guard table.updateValue(entry.evidence, forKey: entry.componentID) == nil else {
                    throw SignatureCaptureError.invalidEvidence(.keyMismatch)
                }
            }
            self.inventoryID = inventoryID; containers = table; self.failures = failures
        }

        var componentIDs: [RelativePath] { containers.keys.sorted() }

        func evidence(for componentID: RelativePath) -> SignatureEvidence? { containers[componentID] }

        /// Exact numeric membership; there is no architecture-label or nearest-slice fallback.
        func slice(for key: SignatureEvidenceKey) -> SignatureSliceEvidence? {
            guard key.inventoryID == inventoryID, let evidence = containers[key.componentID] else { return nil }
            return evidence.slices.first { $0.key == key.slice }
        }

        func key(componentID: RelativePath, sliceIndex: Int) -> SignatureEvidenceKey? {
            guard let slice = containers[componentID]?.slices.first(where: { $0.key.index == sliceIndex }) else { return nil }
            return SignatureEvidenceKey(inventoryID: inventoryID, componentID: componentID, slice: slice.key)
        }

        /// Membership and numeric binding against the AR1 inventory the evidence was captured under.
        func bind(to inventory: ComponentInventory) throws {
            guard inventory.id == inventoryID else { throw SignatureCaptureError.invalidEvidence(.keyMismatch) }
            for (path, evidence) in containers {
                guard let component = inventory.components.first(where: { $0.path == path }) else {
                    throw SignatureCaptureError.invalidEvidence(.keyMismatch)
                }
                for slice in evidence.slices {
                    let matches = component.slices.contains {
                        $0.index == slice.key.index && $0.cpuType == slice.key.cpuType && $0.cpuSubtype == slice.key.cpuSubtype
                            && $0.headerMagic == slice.key.headerMagic && $0.offset == slice.key.sliceOffset && $0.size == slice.key.sliceSize
                    }
                    guard matches else { throw SignatureCaptureError.invalidEvidence(.keyMismatch) }
                }
            }
        }
    }

    typealias SignatureSink = (_ componentID: RelativePath, _ result: Result<SignatureEvidence, SignatureCaptureError>) -> Void
}

extension ComponentEvidence.SignatureEvidenceReader {
    /// Captures from an image descriptor the caller already holds. No path is reopened. Every read and the
    /// descriptor revalidation go through the same operations table, and the shared ledger is charged.
    static func captureHeld(ops: ComponentEvidence.DescriptorOps, handle: Int32, range: ComponentEvidence.PathRange,
                            before: Darwin.stat, ledger: inout ComponentEvidence.ReadLedger)
        -> Result<ComponentEvidence.SignatureEvidence, ComponentEvidence.SignatureCaptureError> {
        typealias Failure = ComponentEvidence.SignatureCaptureError
        func mapped(_ error: Error, _ operation: ComponentEvidence.SignatureOperation, _ offset: UInt64, _ count: Int) -> Failure {
            if let known = error as? Failure { return known }
            switch error as? ComponentEvidence.EvidenceError {
            case .io(_, let code, _)?: return .unavailable(operation, errno: code, range: nil)
            case .shortRead(_, let expected, let actual)?:
                return .shortRead(range: ComponentEvidence.ByteRange(uncheckedStart: offset, end: offset + UInt64(count)),
                                  expected: expected, actual: actual)
            default: return .unavailable(operation, errno: nil, range: nil)
            }
        }
        do {
            return .success(try capture(size: UInt64(max(0, before.st_size)), ledger: &ledger, revalidate: {
                do {
                    guard ComponentEvidence.DescriptorOps.same(before, try ops.stat(handle, range)) else { throw Failure.changedInput }
                } catch { throw mapped(error, .revalidate, 0, 0) }
            }, read: { offset, count in
                do { return try ops.read(handle, offset: offset, count: count, range) } catch { throw mapped(error, .read, offset, count) }
            }))
        } catch {
            return .failure(mapped(error, .read, 0, 0))
        }
    }
}
