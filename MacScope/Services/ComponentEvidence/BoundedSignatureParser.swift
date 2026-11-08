// Original to this item (AR2). A strict all-slot range walk over one bounded signature region.
// Adapted in structure (checked 64-bit arithmetic, typed refusals) from the bounded SuperBlob parsing in the
// AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214; MacScope adds the
// refusal order, the overlap and magic rules, and the slice-location checks.

import Foundation

extension ComponentEvidence {
    /// A structural refusal. A refusal invalidates the whole admitted slot inventory of one slice.
    enum SignatureRefusal: Sendable, Hashable {
        case superBlobHeaderTruncated
        case superBlobMagicMismatch(observed: UInt32)
        case declaredLengthInvalid(declared: UInt32, available: Int)
        case indexTablePastDeclaredLength(count: UInt32, declaredLength: UInt32)
        case duplicateSlotType(UInt32)
        case slotOffsetInsideIndex(slot: UInt32, offset: UInt32)
        case slotOffsetPastDeclaredLength(slot: UInt32, offset: UInt32, declaredLength: UInt32)
        case blobHeaderTruncated(slot: UInt32, offset: UInt32)
        case blobLengthInvalid(slot: UInt32, length: UInt32)
        case blobExtentPastDeclaredLength(slot: UInt32, offset: UInt32, length: UInt32, declaredLength: UInt32)
        case entitlementTypeMagicMismatch(slot: UInt32, magic: UInt32)
        case overlappingBlobRanges(firstIndex: Int, firstRange: ByteRange, secondIndex: Int, secondRange: ByteRange)
        case signatureCommandDuplicate
        case signatureRangeOutsideSlice
        case signatureRangeOverlapsCommands
    }

    /// One indexed blob. Offsets are relative to the start of the retained signature region.
    struct SignatureSlotRecord: Sendable, Hashable {
        let index: Int
        let slot: UInt32
        let offset: UInt32
        let length: UInt32
        let magic: UInt32
        /// Exact interval within the signature region.
        var regionRange: ByteRange { ByteRange(uncheckedStart: UInt64(offset), end: UInt64(offset) + UInt64(length)) }
    }

    struct ParsedSignatureRegion: Sendable, Hashable {
        let regionByteCount: Int
        let declaredLength: UInt32
        let slots: [SignatureSlotRecord]
        /// Bytes after the declared length through the load-command data size: kept and hashed, never parsed.
        let trailingByteCount: Int
    }

    enum SignatureParseOutcome: Sendable, Hashable {
        case parsed(ParsedSignatureRegion)
        case refused(SignatureRefusal)
        /// A reached cap: PARTIAL. `declaredCount` is the unvalidated header count when the cap names slots.
        case capped(CaptureLimit, declaredCount: Int?)
    }

    /// Where the signature command points inside one slice.
    struct SignatureCommandLocation: Sendable, Hashable {
        let offset: UInt32
        let size: UInt32
    }

    struct BoundedSignatureParser: Sendable {
        let limits: SignatureEvidenceLimits
        init(limits: SignatureEvidenceLimits = SignatureEvidenceLimits()) { self.limits = limits }

        private static func be32(_ bytes: [UInt8], _ at: Int) -> UInt32 {
            (0..<4).reduce(UInt32(0)) { $0 << 8 | UInt32(bytes[at + $1]) }
        }

        /// Refusals in the design order. Configuration errors throw; everything else is an outcome.
        func parse(region: [UInt8]) throws -> SignatureParseOutcome {
            try limits.validate()
            if region.count > limits.signatureBytes { return .capped(.signatureBytes, declaredCount: nil) }
            let headerSize = Int(MachOConstants.codeSignatureSuperBlobHeaderSize)
            guard region.count >= headerSize else { return .refused(.superBlobHeaderTruncated) }
            let magic = Self.be32(region, 0)
            guard magic == MachOConstants.codeSignatureEmbeddedSignatureMagic else {
                return .refused(.superBlobMagicMismatch(observed: magic))
            }
            let declared = Self.be32(region, 4), count = Self.be32(region, 8)
            guard declared >= MachOConstants.codeSignatureSuperBlobHeaderSize, UInt64(declared) <= UInt64(region.count) else {
                return .refused(.declaredLengthInvalid(declared: declared, available: region.count))
            }
            guard UInt64(count) <= (UInt64(declared) - UInt64(headerSize)) / 8 else {
                return .refused(.indexTablePastDeclaredLength(count: count, declaredLength: declared))
            }
            if Int(count) > limits.slots { return .capped(.slots, declaredCount: Int(count)) }
            let indexEnd = UInt64(headerSize) + UInt64(count) * 8
            var slots: [SignatureSlotRecord] = []
            var seen = Set<UInt32>()
            for index in 0..<Int(count) {
                let base = headerSize + index * 8
                let slot = Self.be32(region, base), offset = Self.be32(region, base + 4)
                guard seen.insert(slot).inserted else { return .refused(.duplicateSlotType(slot)) }
                guard UInt64(offset) >= indexEnd else { return .refused(.slotOffsetInsideIndex(slot: slot, offset: offset)) }
                guard offset <= declared else {
                    return .refused(.slotOffsetPastDeclaredLength(slot: slot, offset: offset, declaredLength: declared))
                }
                let blobHeader = Int(MachOConstants.codeSignatureBlobHeaderSize)
                guard UInt64(offset) + UInt64(blobHeader) <= UInt64(declared) else {
                    return .refused(.blobHeaderTruncated(slot: slot, offset: offset))
                }
                let blobMagic = Self.be32(region, Int(offset)), length = Self.be32(region, Int(offset) + 4)
                guard length >= MachOConstants.codeSignatureBlobHeaderSize else { return .refused(.blobLengthInvalid(slot: slot, length: length)) }
                guard UInt64(length) <= UInt64(declared) - UInt64(offset) else {
                    return .refused(.blobExtentPastDeclaredLength(slot: slot, offset: offset, length: length, declaredLength: declared))
                }
                let isEntitlementMagic = blobMagic == MachOConstants.codeSignatureEmbeddedEntitlementsMagic
                    || blobMagic == MachOConstants.codeSignatureDerEntitlementsMagic
                let mismatch: Bool
                switch slot {
                case MachOConstants.codeSignatureSlotEntitlements: mismatch = blobMagic != MachOConstants.codeSignatureEmbeddedEntitlementsMagic
                case MachOConstants.codeSignatureSlotDerEntitlements: mismatch = blobMagic != MachOConstants.codeSignatureDerEntitlementsMagic
                default: mismatch = isEntitlementMagic
                }
                if mismatch { return .refused(.entitlementTypeMagicMismatch(slot: slot, magic: blobMagic)) }
                slots.append(SignatureSlotRecord(index: index, slot: slot, offset: offset, length: length, magic: blobMagic))
            }
            // Overlap: sorted by start (table order breaks ties); a running maximum end catches containment.
            let ordered = slots.sorted { ($0.offset, $0.index) < ($1.offset, $1.index) }
            var reach: SignatureSlotRecord?
            for next in ordered {
                if let owner = reach, UInt64(next.offset) < UInt64(owner.offset) + UInt64(owner.length) {
                    return .refused(.overlappingBlobRanges(firstIndex: owner.index, firstRange: owner.regionRange,
                                                           secondIndex: next.index, secondRange: next.regionRange))
                }
                if reach == nil || UInt64(next.offset) + UInt64(next.length) > UInt64(reach!.offset) + UInt64(reach!.length) { reach = next }
            }
            return .parsed(ParsedSignatureRegion(regionByteCount: region.count, declaredLength: declared, slots: slots,
                                                 trailingByteCount: region.count - Int(declared)))
        }

        /// Scans one little-endian 64-bit command sequence. `headerSize` is 32. A sequence that does not tile
        /// exactly throws; a duplicate or misplaced signature command is a refusal for the slice.
        static func locateSignatureCommand(commands: [UInt8], commandCount: Int, headerSize: Int, sliceSize: UInt64)
            throws -> (location: SignatureCommandLocation?, refusal: SignatureRefusal?) {
            func le32(_ at: Int) -> UInt32 { (0..<4).reduce(UInt32(0)) { $0 | UInt32(commands[at + $1]) << UInt32($1 * 8) } }
            var position = 0
            var found: (offset: UInt32, size: UInt32, length: UInt32)?
            var duplicate = false
            for _ in 0..<commandCount {
                guard position <= commands.count - 8 else { throw SignatureCaptureError.invalidContainer(.malformedLoadCommands) }
                let cmd = le32(position), length = Int(le32(position + 4))
                guard length >= 8, length % 8 == 0, length <= commands.count - position else {
                    throw SignatureCaptureError.invalidContainer(.malformedLoadCommands)
                }
                if cmd == MachOConstants.loadCommandCodeSignature {
                    if found != nil { duplicate = true } else if length >= 16 {
                        found = (le32(position + 8), le32(position + 12), UInt32(length))
                    } else {
                        found = (0, 0, UInt32(length))
                    }
                }
                position += length
            }
            guard position == commands.count else { throw SignatureCaptureError.invalidContainer(.malformedLoadCommands) }
            if duplicate { return (nil, .signatureCommandDuplicate) }
            guard let command = found else { return (nil, nil) }
            guard command.length == 16, command.size > 0, UInt64(command.offset) <= sliceSize,
                  UInt64(command.size) <= sliceSize - UInt64(command.offset) else { return (nil, .signatureRangeOutsideSlice) }
            guard UInt64(command.offset) >= UInt64(headerSize + commands.count) else { return (nil, .signatureRangeOverlapsCommands) }
            return (SignatureCommandLocation(offset: command.offset, size: command.size), nil)
        }
    }
}
