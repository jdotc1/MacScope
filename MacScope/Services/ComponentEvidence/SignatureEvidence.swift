// Original to this item (AR2). Immutable raw code-signature evidence values: bytes, not trust.
// Nothing here validates a signature, a trust chain, notarization or effective permissions.

import Foundation

extension ComponentEvidence {
    /// Half-open byte interval. `start <= end` always.
    struct ByteRange: Sendable, Hashable {
        let start: UInt64
        let end: UInt64
        init(start: UInt64, end: UInt64) throws {
            guard start <= end else { throw SignatureCaptureError.invalidEvidence(.addressOverflow) }
            self.start = start; self.end = end
        }
        init(start: UInt64, length: UInt64) throws {
            guard length <= UInt64.max - start else { throw SignatureCaptureError.invalidEvidence(.addressOverflow) }
            self.start = start; self.end = start + length
        }
        var length: UInt64 { end - start }
        func overlaps(_ other: ByteRange) -> Bool { start < other.end && other.start < end }
    }

    /// The bounded quantities AR2 can reach. A reached limit is always PARTIAL, never a silent absence.
    enum CaptureLimit: String, Sendable, Hashable {
        case containerHashBytes, headerBytes, loadCommands, slices, signatureBytes, totalSignatureBytes, slots
    }

    /// Why a counted omission is known: from an enumerated list or from a declared header domain.
    enum ObservationBasis: String, Sendable, Hashable { case enumeratedList, declaredHeaderDomain, notApplicable }

    /// Closed kind of an underlying read failure. Display strings are labels only.
    enum ReadFailureKind: Sendable, Hashable {
        case readError(errno: Int32)
        case shortRead(expected: Int, actual: Int)
        case other
    }

    /// Why a value is unavailable. Never an absence.
    enum SignatureEvidenceProblem: Sendable, Hashable {
        case unsupportedArchitecture
        case readFailed(ReadFailureKind)
        case capReached(CaptureLimit)
        case structureRefused(SignatureRefusal)
        case codeDirectoryHeaderTruncated
        case codeDirectoryTypeMagicMismatch
        case unsupportedDigestAlgorithm(UInt8)
        case notExamined
    }

    enum InvalidEvidenceReason: String, Sendable, Hashable {
        case addressOverflow, rangeAttributionMismatch, incoherentPresence, incoherentCompletion
        case digestWithoutSource, countMismatch, keyMismatch, absenceNotProved, incoherentState
    }

    enum SignatureLimitName: String, Sendable, Hashable {
        case containerHashBytes, headerBytes, signatureBytes, totalSignatureBytes, slots, slices, loadCommands, hashChunk
    }

    enum SignatureContainerReason: String, Sendable, Hashable {
        case emptyImage, unsupportedMagic, invalidFatLayout, fatSliceIdentityMismatch, overlappingFatSlices
        case malformedHeader, malformedLoadCommands
    }

    enum SignatureOperation: String, Sendable, Hashable { case read, hash, revalidate }

    /// Capture-wide faults. Each throws and publishes nothing.
    enum SignatureCaptureError: Error, Sendable, Hashable {
        case invalidEvidence(InvalidEvidenceReason)
        case invalidLimits(SignatureLimitName)
        case invalidContainer(SignatureContainerReason)
        case staleCapability
        case changedInput
        case wrongSlice
        case unavailable(SignatureOperation, errno: Int32?, range: ByteRange?)
        case shortRead(range: ByteRange, expected: Int, actual: Int)
        case cancelled

        /// The typed unavailable reason a recorded value carries for a read failure. Never an absence.
        var readFailure: SignatureEvidenceProblem? {
            switch self {
            case .unavailable(_, let code, _): .readFailed(code.map { .readError(errno: $0) } ?? .other)
            case .shortRead(_, let expected, let actual): .readFailed(.shortRead(expected: expected, actual: actual))
            default: nil
            }
        }
    }

    /// Bounded numeric ceilings. Hard ceilings cannot be raised.
    struct SignatureEvidenceLimits: Sendable, Hashable {
        static let hardContainerHashBytes = 536_870_912
        static let hardHeaderBytes = 1_048_576
        static let hardSignatureBytes = 524_288
        static let hardTotalSignatureBytes = 4_194_304
        static let hardSlots = 4096
        static let hardSlices = 64
        static let hardLoadCommands = 4096
        static let hardHashChunk = 65_536

        var containerHashBytes = SignatureEvidenceLimits.hardContainerHashBytes
        var headerBytes = SignatureEvidenceLimits.hardHeaderBytes
        var signatureBytes = SignatureEvidenceLimits.hardSignatureBytes
        var totalSignatureBytes = SignatureEvidenceLimits.hardTotalSignatureBytes
        var slots = SignatureEvidenceLimits.hardSlots
        var slices = SignatureEvidenceLimits.hardSlices
        var loadCommands = SignatureEvidenceLimits.hardLoadCommands
        var hashChunk = SignatureEvidenceLimits.hardHashChunk

        /// Every value positive and no larger than its hard ceiling.
        func validate() throws {
            let checks: [(Int, Int, SignatureLimitName)] = [
                (containerHashBytes, Self.hardContainerHashBytes, .containerHashBytes),
                (headerBytes, Self.hardHeaderBytes, .headerBytes), (signatureBytes, Self.hardSignatureBytes, .signatureBytes),
                (totalSignatureBytes, Self.hardTotalSignatureBytes, .totalSignatureBytes), (slots, Self.hardSlots, .slots),
                (slices, Self.hardSlices, .slices), (loadCommands, Self.hardLoadCommands, .loadCommands),
                (hashChunk, Self.hardHashChunk, .hashChunk)]
            for (value, ceiling, name) in checks where value <= 0 || value > ceiling { throw SignatureCaptureError.invalidLimits(name) }
        }
    }

    /// One complete blob with its 8-byte header. Offsets are exact.
    struct SignatureBlobEvidence: Sendable, Hashable {
        let type: UInt32
        let magic: UInt32
        let bytes: [UInt8]
        let sha256: [UInt8]
        let containerOffset: UInt64
        let sliceRelativeOffset: UInt64
        var byteCount: Int { bytes.count }
        /// Payload after the 8-byte header.
        var payload: [UInt8] { Array(bytes.dropFirst(8)) }

        init(type: UInt32, magic: UInt32, bytes: [UInt8], sha256: [UInt8], containerOffset: UInt64, sliceRelativeOffset: UInt64) throws {
            guard bytes.count >= 8, sha256.count == 32, containerOffset >= sliceRelativeOffset else {
                throw SignatureCaptureError.invalidEvidence(.rangeAttributionMismatch)
            }
            self.type = type; self.magic = magic; self.bytes = bytes; self.sha256 = sha256
            self.containerOffset = containerOffset; self.sliceRelativeOffset = sliceRelativeOffset
        }
    }

    /// The identity of one slice by numeric facts only. An architecture label is never a join key.
    struct SignatureSliceKey: Sendable, Hashable {
        let index: Int
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let headerMagic: UInt32
        let sliceOffset: UInt64
        let sliceSize: UInt64
    }

    enum DigestAlgorithm: String, Sendable, Hashable { case sha1, sha256, sha256Truncated20, sha384 }

    /// A digest with its exact source, or a typed reason it is unavailable. A prefix hash is never an identity.
    enum DigestObservation: Sendable, Hashable {
        case complete(algorithm: DigestAlgorithm, bytes: [UInt8], source: ByteRange)
        case unavailable(SignatureEvidenceProblem)
        case prefix(range: ByteRange, digest: [UInt8])

        /// Lowercase hexadecimal of the full stored length; nil unless complete.
        var hex: String? {
            guard case .complete(_, let bytes, _) = self else { return nil }
            return bytes.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined()
        }
    }

    /// Present carries the value; notPresent carries nothing; unavailable carries its typed reason.
    enum EvidencePresence<Value: Sendable & Hashable>: Sendable, Hashable {
        case present(Value)
        case notPresent
        case unavailable(SignatureEvidenceProblem)
        var value: Value? { if case .present(let value) = self { value } else { nil } }
    }

    /// The whole retained signature region of one slice, byte exact.
    struct SignatureRegionEvidence: Sendable, Hashable {
        let bytes: [UInt8]
        let sha256: [UInt8]
        let sliceRelativeOffset: UInt64
        let containerOffset: UInt64
        let declaredLength: UInt32?
        let trailingByteCount: Int
    }

    typealias SignatureObservation = EvidencePresence<SignatureRegionEvidence>
    typealias SlotInventoryObservation = EvidencePresence<[SignatureSlotRecord]>

    enum SignatureEvidenceState: Sendable, Hashable {
        case collected
        case signatureAbsent
        case entitlementsAbsent
        case unexamined(SignatureEvidenceProblem)
        case malformed(SignatureRefusal)
        case budgetExceeded(CaptureLimit)
    }

    /// Raw evidence of one slice. Raw blobs are never replaced by normalized dictionaries.
    struct SignatureSliceEvidence: Sendable, Hashable {
        let key: SignatureSliceKey
        let state: SignatureEvidenceState
        let sliceSHA256: DigestObservation
        let signature: SignatureObservation
        let slots: SlotInventoryObservation
        let entitlementsXML: EvidencePresence<SignatureBlobEvidence>
        let entitlementsDER: EvidencePresence<SignatureBlobEvidence>
        let codeDirectories: EvidencePresence<[CodeDirectoryEvidence]>

        init(key: SignatureSliceKey, state: SignatureEvidenceState, sliceSHA256: DigestObservation, signature: SignatureObservation,
             slots: SlotInventoryObservation, entitlementsXML: EvidencePresence<SignatureBlobEvidence>,
             entitlementsDER: EvidencePresence<SignatureBlobEvidence>,
             codeDirectories: EvidencePresence<[CodeDirectoryEvidence]>) throws {
            switch state {
            case .signatureAbsent:
                guard signature == .notPresent, slots == .notPresent, entitlementsXML == .notPresent,
                      entitlementsDER == .notPresent, codeDirectories == .notPresent else {
                    throw SignatureCaptureError.invalidEvidence(.incoherentPresence)
                }
            case .unexamined(.unsupportedArchitecture):
                guard case .unavailable(.unsupportedArchitecture) = signature, signature.value == nil else {
                    throw SignatureCaptureError.invalidEvidence(.incoherentPresence)
                }
            case .unexamined:
                break
            case .entitlementsAbsent:
                guard signature.value != nil, entitlementsXML == .notPresent, entitlementsDER == .notPresent else {
                    throw SignatureCaptureError.invalidEvidence(.absenceNotProved)
                }
            case .collected:
                guard entitlementsXML.value != nil || entitlementsDER.value != nil else {
                    throw SignatureCaptureError.invalidEvidence(.incoherentState)
                }
            case .malformed, .budgetExceeded:
                guard entitlementsXML.value == nil, entitlementsDER.value == nil, slots.value == nil else {
                    throw SignatureCaptureError.invalidEvidence(.incoherentPresence)
                }
            }
            if case .complete(_, let bytes, let source) = sliceSHA256 {
                guard bytes.count == 32, source.start == key.sliceOffset, source.length == key.sliceSize else {
                    throw SignatureCaptureError.invalidEvidence(.digestWithoutSource)
                }
            }
            self.key = key; self.state = state; self.sliceSHA256 = sliceSHA256; self.signature = signature
            self.slots = slots; self.entitlementsXML = entitlementsXML; self.entitlementsDER = entitlementsDER
            self.codeDirectories = codeDirectories
        }
    }

    /// What a reached limit cost. Counts are nil when any summand is unknown, never 0.
    struct CaptureLoss: Sendable, Hashable {
        let limit: CaptureLimit
        let configured: Int
        let attempted: Int?
        let range: ByteRange?
        let basis: ObservationBasis
    }

    enum KnownMismatch: Sendable, Hashable {
        case limitReached(CaptureLimit)
        case declaredSliceCountAboveCap(declared: Int)
    }

    struct PartialCapture: Sendable, Hashable {
        let losses: [CaptureLoss]
        let knownMismatches: [KnownMismatch]
        let hashedContainerRange: ByteRange
        let successfullyReadRanges: [ByteRange]
        let bytesHashed: UInt64
        let observedOmittedSliceCount: Int?
        let observedOmittedIndexedBlobCount: Int?
        let remainderUnknown: Bool

        init(losses: [CaptureLoss], knownMismatches: [KnownMismatch], hashedContainerRange: ByteRange, successfullyReadRanges: [ByteRange],
             bytesHashed: UInt64, observedOmittedSliceCount: Int?, observedOmittedIndexedBlobCount: Int?) throws {
            guard !losses.isEmpty, hashedContainerRange.start == 0, hashedContainerRange.end == bytesHashed else {
                throw SignatureCaptureError.invalidEvidence(.incoherentCompletion)
            }
            self.losses = losses; self.knownMismatches = knownMismatches; self.hashedContainerRange = hashedContainerRange
            self.successfullyReadRanges = Self.normalized(successfullyReadRanges)
            self.bytesHashed = bytesHashed
            self.observedOmittedSliceCount = observedOmittedSliceCount
            self.observedOmittedIndexedBlobCount = observedOmittedIndexedBlobCount
            remainderUnknown = true
        }

        /// Sorted union that preserves holes and merges only touching or overlapping intervals.
        static func normalized(_ ranges: [ByteRange]) -> [ByteRange] {
            var out: [ByteRange] = []
            for range in ranges.sorted(by: { ($0.start, $0.end) < ($1.start, $1.end) }) where range.length > 0 {
                if let last = out.last, range.start <= last.end {
                    out[out.count - 1] = ByteRange(uncheckedStart: last.start, end: max(last.end, range.end))
                } else {
                    out.append(range)
                }
            }
            return out
        }
    }

    enum CaptureCompletion: Sendable, Hashable {
        case complete
        case partial(PartialCapture)
    }

    /// Counters frozen at publication. Charged counts include failed attempts; actual counts only successful bytes.
    struct SignatureReadLedgerSnapshot: Sendable, Hashable {
        let headerBytesCharged: Int
        let headerBytesRead: Int
        let signatureBytesCharged: Int
        let signatureBytesRead: Int
        let bytesHashed: UInt64
        let sharedLedgerUsedAtEnd: Int
    }

    /// Whole-container evidence. `declaredSliceCount` is unvalidated header information, carried only on the slice cap.
    struct SignatureEvidence: Sendable, Hashable {
        let containerSize: UInt64
        let containerSHA256: DigestObservation
        let slices: [SignatureSliceEvidence]
        let completion: CaptureCompletion
        let declaredSliceCount: Int?
        let ledger: SignatureReadLedgerSnapshot

        init(containerSize: UInt64, containerSHA256: DigestObservation, slices: [SignatureSliceEvidence],
             completion: CaptureCompletion, declaredSliceCount: Int?, ledger: SignatureReadLedgerSnapshot) throws {
            if case .complete(_, let bytes, let source) = containerSHA256 {
                guard bytes.count == 32, source.start == 0, source.end == containerSize else {
                    throw SignatureCaptureError.invalidEvidence(.digestWithoutSource)
                }
            }
            if case .complete = completion {
                guard declaredSliceCount == nil else { throw SignatureCaptureError.invalidEvidence(.incoherentCompletion) }
                for slice in slices {
                    switch slice.state {
                    case .budgetExceeded: throw SignatureCaptureError.invalidEvidence(.incoherentCompletion)
                    default: break
                    }
                }
            }
            for (position, slice) in slices.enumerated() where slice.key.index != position {
                throw SignatureCaptureError.invalidEvidence(.keyMismatch)
            }
            self.containerSize = containerSize; self.containerSHA256 = containerSHA256; self.slices = slices
            self.completion = completion; self.declaredSliceCount = declaredSliceCount; self.ledger = ledger
        }
    }
}

extension ComponentEvidence.ByteRange {
    /// Only for results of arithmetic already proved ordered.
    init(uncheckedStart start: UInt64, end: UInt64) { self.start = start; self.end = end }
}
