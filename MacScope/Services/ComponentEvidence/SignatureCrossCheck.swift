// Original to this item (AR2). A pure, test-driven comparison of the strict AR2 slice evidence against two
// observations the caller already obtained from the legacy readers (MachOParser and MachOLoadMetadata).
// It calls neither legacy parser, re-reads no file and retains no bytes. A difference is reported, never normalized.
// Production capture does not call it (AQ5): production records the cross-check as not performed.

import CryptoKit
import Foundation

extension ComponentEvidence {
    /// What the strict legacy MachOParser returned for the exact thin-slice bytes.
    enum LegacyStrictObservation: Sendable {
        /// The parser returned. `nil` means no signature command; a signature with a nil superBlob is unavailable structure.
        case accepted(MachOCodeSignature?)
        /// The parser threw. The bounded reason is retained and is never an absence.
        case rejected(reason: String)
    }

    /// What the lenient MachOLoadMetadata reader returned for the same bytes.
    enum LegacyMetadataObservation: Sendable {
        /// `nil` is ambiguous: it never proves absence on its own.
        case summary(MachOLoadMetadata.CodeSignatureInfo?)
        case rejected(reason: String)
    }

    enum SignatureCheckLeg: String, Sendable, Hashable {
        case sliceBinding, structuralAdmission, slotInventory, entitlementSummary, codeDirectorySummary
        case entitlementValues, digestCorrectness, lenientCodeDirectory, lenientDERValue
    }

    enum SignatureCheckCoverage: Sendable, Hashable {
        case compared
        case notPerformed(reason: String)
        case notCovered(reason: String)
    }

    enum SignatureDifference: Sendable, Hashable {
        case legacyAcceptedStrictRefusal(SignatureRefusal)
        case legacyRejectedStrictAccepted(legacyReason: String)
        case availabilityDisagreement
        case slotInventoryDisagreement
        case summaryDisagreement(field: String)
        case valueDisagreement(form: EntitlementForm)
        case legacyProjectionLoss(field: String)
    }

    struct SignatureLegResult: Sendable, Hashable {
        let leg: SignatureCheckLeg
        let coverage: SignatureCheckCoverage
    }

    struct SignatureCrossCheckResult: Sendable, Hashable {
        let key: SignatureSliceKey
        /// The expected slice digest the comparison was bound to.
        let sliceSHA256: [UInt8]
        let legs: [SignatureLegResult]
        let differences: [SignatureDifference]
        func coverage(of leg: SignatureCheckLeg) -> SignatureCheckCoverage? { legs.first { $0.leg == leg }?.coverage }
    }

    enum SignatureCrossCheck {
        static let notRetainedReason = "boundedCaptureDoesNotRetainWholeSliceForLegacyParser"

        static func compare(sliceBytes: [UInt8], key: SignatureSliceKey, expectedSliceSHA256: [UInt8],
                            strict: SignatureSliceEvidence, legacyStrict: LegacyStrictObservation,
                            legacyMetadata: LegacyMetadataObservation) -> SignatureCrossCheckResult {
            var run = Run(strict: strict)
            run.execute(sliceBytes: sliceBytes, key: key, expected: expectedSliceSHA256, legacyStrict: legacyStrict, legacyMetadata: legacyMetadata)
            return SignatureCrossCheckResult(key: key, sliceSHA256: expectedSliceSHA256, legs: run.legs, differences: run.differences)
        }

        private struct Run {
            let strict: SignatureSliceEvidence
            var legs: [SignatureLegResult] = []
            var differences: [SignatureDifference] = []
            init(strict: SignatureSliceEvidence) { self.strict = strict }

            mutating func add(_ leg: SignatureCheckLeg, _ coverage: SignatureCheckCoverage) {
                legs.append(SignatureLegResult(leg: leg, coverage: coverage))
            }

            mutating func finishNotPerformed(_ reason: String, from remaining: [SignatureCheckLeg]) {
                for leg in remaining { add(leg, .notPerformed(reason: reason)) }
                addUncovered()
            }

            mutating func addUncovered() {
                add(.digestCorrectness, .notCovered(reason: "legacySummariesContainNoDigest"))
                add(.lenientCodeDirectory, .notCovered(reason: "lenientReaderHasNoCodeDirectoryLeg"))
                add(.lenientDERValue, .notCovered(reason: "derValuesAreNeverDecodedByLenientReader"))
            }

            static let allAfterAdmission: [SignatureCheckLeg] = [.slotInventory, .entitlementSummary, .codeDirectorySummary, .entitlementValues]

            mutating func execute(sliceBytes: [UInt8], key: SignatureSliceKey, expected: [UInt8],
                                  legacyStrict: LegacyStrictObservation, legacyMetadata: LegacyMetadataObservation) {
                let everything: [SignatureCheckLeg] = [.sliceBinding, .structuralAdmission] + Self.allAfterAdmission
                // Binding: exact key, exact slice digest of the supplied bytes, and the strict evidence digest.
                if strict.key != key { return finishNotPerformed("sliceKeyMismatch", from: everything) }
                if Array(SHA256.hash(data: sliceBytes)) != expected { return finishNotPerformed("sliceBytesDigestMismatch", from: everything) }
                if case .complete(_, let stored, _) = strict.sliceSHA256, stored != expected {
                    return finishNotPerformed("strictEvidenceDigestMismatch", from: everything)
                }
                add(.sliceBinding, .compared)
                add(.structuralAdmission, .compared)
                var blobs: [MachOCodeSignatureBlob] = []
                switch (strict.state, legacyStrict) {
                case (.unexamined, _), (.budgetExceeded, _):
                    legs.removeLast()
                    add(.structuralAdmission, .notPerformed(reason: "strictEvidenceNotExamined"))
                    return finishNotPerformed("strictEvidenceNotExamined", from: Self.allAfterAdmission)
                case (.signatureAbsent, .accepted(let signature)):
                    if signature != nil { differences.append(.availabilityDisagreement) }
                    return finishNotPerformed("noSignatureCommand", from: Self.allAfterAdmission)
                case (.signatureAbsent, .rejected(let reason)):
                    differences.append(.legacyRejectedStrictAccepted(legacyReason: reason))
                    return finishNotPerformed("noSignatureCommand", from: Self.allAfterAdmission)
                case (.malformed(let refusal), .accepted(let signature)):
                    if let found = signature?.superBlob?.blobs, !found.isEmpty { differences.append(.legacyAcceptedStrictRefusal(refusal)) }
                    return finishNotPerformed("strictRefusal", from: Self.allAfterAdmission)
                case (.malformed, .rejected):
                    return finishNotPerformed("strictRefusal", from: Self.allAfterAdmission)
                case (.collected, .rejected(let reason)), (.entitlementsAbsent, .rejected(let reason)):
                    differences.append(.legacyRejectedStrictAccepted(legacyReason: reason))
                    return finishNotPerformed("legacyRejected", from: Self.allAfterAdmission)
                case (.collected, .accepted(let signature)), (.entitlementsAbsent, .accepted(let signature)):
                    guard let found = signature?.superBlob?.blobs else {
                        // A kept signature without a readable superblob is unavailable structure, not absence.
                        differences.append(.availabilityDisagreement)
                        return finishNotPerformed("legacyStructureUnavailable", from: Self.allAfterAdmission)
                    }
                    blobs = found
                }
                compareSlots(blobs)
                compareSummaries(legacyMetadata)
                addUncovered()
            }

            mutating func compareSlots(_ blobs: [MachOCodeSignatureBlob]) {
                guard let slots = strict.slots.value else {
                    add(.slotInventory, .notPerformed(reason: "strictSlotsUnavailable"))
                    add(.codeDirectorySummary, .notPerformed(reason: "strictSlotsUnavailable"))
                    add(.entitlementSummary, .notPerformed(reason: "strictSlotsUnavailable"))
                    return
                }
                add(.slotInventory, .compared)
                let left = slots.map { [UInt64($0.slot), UInt64($0.offset), UInt64($0.magic), UInt64($0.length)] }
                let right = blobs.map { [UInt64($0.type), UInt64($0.relativeOffset), UInt64($0.magic), UInt64($0.length)] }
                if left != right { differences.append(.slotInventoryDisagreement) }
                // CodeDirectory header summary, keeping the blob-to-slot association.
                let directories = strict.codeDirectories.value ?? []
                add(.codeDirectorySummary, .compared)
                for directory in directories {
                    guard let blob = blobs.first(where: { $0.type == directory.slot }) else {
                        differences.append(.slotInventoryDisagreement); continue
                    }
                    guard let summary = blob.codeDirectory else {
                        if directory.hashType != nil { differences.append(.summaryDisagreement(field: "codeDirectory.present")) }
                        continue
                    }
                    if let type = directory.hashType, type != summary.hashType { differences.append(.summaryDisagreement(field: "codeDirectory.hashType")) }
                    if let size = directory.hashSize, size != summary.hashSize { differences.append(.summaryDisagreement(field: "codeDirectory.hashSize")) }
                }
                let strictDirectorySlots = Set(directories.map(\.slot))
                for blob in blobs where blob.codeDirectory != nil && !strictDirectorySlots.contains(blob.type) {
                    differences.append(.summaryDisagreement(field: "codeDirectory.present"))
                }
                // Entitlement summaries per form.
                add(.entitlementSummary, .compared)
                let forms: [(EntitlementForm, EvidencePresence<SignatureBlobEvidence>)] = [(.xml, strict.entitlementsXML), (.der, strict.entitlementsDER)]
                for (form, presence) in forms {
                    let legacyFormat: MachOCodeSignatureEntitlementsFormat = form == .xml ? .xml : .der
                    let legacy = blobs.compactMap(\.entitlements).filter { $0.format == legacyFormat }
                    switch presence {
                    case .unavailable: continue
                    case .notPresent:
                        if !legacy.isEmpty { differences.append(.summaryDisagreement(field: "\(form.rawValue).presence")) }
                    case .present(let blob):
                        guard let summary = legacy.first else {
                            differences.append(.summaryDisagreement(field: "\(form.rawValue).presence")); continue
                        }
                        guard form == .xml else { continue }
                        guard let dictionary = RawEntitlementAdapter.decodeXML(blob.payload).dictionary else {
                            if summary.isParsed { differences.append(.summaryDisagreement(field: "xml.parsed")) }
                            continue
                        }
                        if !summary.isParsed { differences.append(.summaryDisagreement(field: "xml.parsed")); continue }
                        compareKeys(strict: dictionary.entries.map(\.key), legacy: summary.keys, field: "xml.keys")
                    }
                }
            }

            mutating func compareKeys(strict keys: [String], legacy legacyKeys: [String], field: String) {
                func bytes(_ key: String) -> [UInt8] { Array(key.utf8) }
                let order: (String, String) -> Bool = { bytes($0).lexicographicallyPrecedes(bytes($1)) }
                if keys.sorted(by: order).elementsEqual(legacyKeys.sorted(by: order)) { return }
                // Swift String equality merges canonically equivalent spellings, so a smaller distinct count is projection loss.
                if Set(keys) == Set(legacyKeys), Set(keys).count < keys.count {
                    differences.append(.legacyProjectionLoss(field: field))
                } else {
                    differences.append(.summaryDisagreement(field: field))
                }
            }

            mutating func compareSummaries(_ observation: LegacyMetadataObservation) {
                switch observation {
                case .rejected(let reason):
                    add(.entitlementValues, .notPerformed(reason: "legacyMetadataRejected"))
                    differences.append(.legacyRejectedStrictAccepted(legacyReason: reason))
                case .summary(let info):
                    guard let info else {
                        // A nil lenient summary is ambiguous. It disagrees only when the strict evidence found entitlements.
                        add(.entitlementValues, .notPerformed(reason: "lenientSummaryAbsentIsAmbiguous"))
                        if strict.entitlementsXML.value != nil || strict.entitlementsDER.value != nil { differences.append(.availabilityDisagreement) }
                        return
                    }
                    add(.entitlementValues, .compared)
                    let hasXML = strict.entitlementsXML.value != nil, hasDER = strict.entitlementsDER.value != nil
                    if info.entitlementsDER != hasDER { differences.append(.summaryDisagreement(field: "der.presence")) }
                    if hasXML && info.entitlementsFormat == nil { differences.append(.summaryDisagreement(field: "xml.presence")) }
                    if hasXML, !hasDER, let format = info.entitlementsFormat, format != "XML" {
                        differences.append(.summaryDisagreement(field: "entitlementsFormat"))
                    }
                    if hasDER, !hasXML, let format = info.entitlementsFormat, format != "DER" {
                        differences.append(.summaryDisagreement(field: "entitlementsFormat"))
                    }
                    if hasXML, hasDER, info.entitlementsFormat == "DER", info.entitlementsXML != nil {
                        // The lenient reader may keep XML fields from an earlier slot while a later DER slot sets the format.
                        differences.append(.summaryDisagreement(field: "entitlementsFormat"))
                    }
                    if let blob = strict.entitlementsXML.value, let text = info.entitlementsXML {
                        let left = RawEntitlementAdapter.decodeXML(blob.payload).dictionary
                        let right = RawEntitlementAdapter.decodeXML(Array(text.utf8)).dictionary
                        if left != right { differences.append(.valueDisagreement(form: .xml)) }
                    }
                }
            }
        }
    }
}
