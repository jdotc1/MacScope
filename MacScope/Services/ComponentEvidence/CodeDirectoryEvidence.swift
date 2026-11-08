// Original to this item (AR2). CodeDirectory records retained as raw ranges with the canonical declared digest.
// Digest contract (owner ruling O1): the digest of the complete CodeDirectory blob bytes, with that blob's own
// hash type; the full digest is stored and the 20-byte CDHash is derived from it for display and comparison only.
// Nothing here validates code pages, requirements, certificates, signing coverage or trust.

import CryptoKit
import Foundation

extension ComponentEvidence {
    enum CodeDirectoryRole: Sendable, Hashable {
        case primary
        /// Alternate index 0 through 4, from the slot (0x1000 through 0x1004), never from array position.
        case alternate(Int)
        /// A CodeDirectory magic found in a slot that is not a CodeDirectory slot.
        case misplaced
    }

    /// The full stored digest. `derivedCDHash` is the first 20 bytes and is labelled derived.
    struct CodeDirectoryDigest: Sendable, Hashable {
        let algorithm: DigestAlgorithm
        let fullBytes: [UInt8]
        var derivedCDHash: [UInt8] { Array(fullBytes.prefix(20)) }
        var fullHex: String { Self.hex(fullBytes) }
        var derivedCDHashHex: String { Self.hex(derivedCDHash) }
        static func hex(_ bytes: [UInt8]) -> String { bytes.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined() }
    }

    enum CodeDirectoryDigestStatus: Sendable, Hashable {
        case available(CodeDirectoryDigest)
        case unavailable(SignatureEvidenceProblem)
    }

    struct CodeDirectoryEvidence: Sendable, Hashable {
        let slot: UInt32
        let role: CodeDirectoryRole
        /// Exact interval within the retained signature region. No second copy of the bytes is made.
        let regionRange: ByteRange
        let magic: UInt32
        let byteCount: UInt32
        let hashType: UInt8?
        let hashSize: UInt8?
        /// Always the SHA-256 of the whole raw blob; never substituted for a missing declared digest.
        let rawBlobSHA256: [UInt8]
        let digest: CodeDirectoryDigestStatus
    }

    struct CodeDirectoryReader: Sendable {
        /// Ascending numeric slot order. Notpresent when no slot holds a CodeDirectory.
        static func read(slots: [SignatureSlotRecord], region: [UInt8]) -> EvidencePresence<[CodeDirectoryEvidence]> {
            var records: [CodeDirectoryEvidence] = []
            for slot in slots.sorted(by: { $0.slot < $1.slot }) {
                let primary = slot.slot == MachOConstants.codeSignatureSlotCodeDirectory
                let alternate = (MachOConstants.codeSignatureSlotAlternateCodeDirectoryStart...MachOConstants.codeSignatureSlotAlternateCodeDirectoryEnd)
                    .contains(slot.slot)
                let isCodeDirectorySlot = primary || alternate
                let hasMagic = slot.magic == MachOConstants.codeSignatureCodeDirectoryMagic
                guard isCodeDirectorySlot || hasMagic else { continue }
                let blob = Array(region[Int(slot.offset)..<(Int(slot.offset) + Int(slot.length))])
                let role: CodeDirectoryRole = primary ? .primary
                    : alternate ? .alternate(Int(slot.slot - MachOConstants.codeSignatureSlotAlternateCodeDirectoryStart)) : .misplaced
                let rawHash = Array(SHA256.hash(data: blob))
                func record(_ type: UInt8?, _ size: UInt8?, _ status: CodeDirectoryDigestStatus) -> CodeDirectoryEvidence {
                    CodeDirectoryEvidence(slot: slot.slot, role: role, regionRange: slot.regionRange, magic: slot.magic,
                                          byteCount: slot.length, hashType: type, hashSize: size, rawBlobSHA256: rawHash, digest: status)
                }
                guard hasMagic, isCodeDirectorySlot else {
                    records.append(record(nil, nil, .unavailable(.codeDirectoryTypeMagicMismatch)))
                    continue
                }
                guard blob.count >= Int(MachOConstants.codeSignatureCodeDirectoryHeaderSize) else {
                    records.append(record(nil, nil, .unavailable(.codeDirectoryHeaderTruncated)))
                    continue
                }
                let hashSize = blob[36], hashType = blob[37]
                records.append(record(hashType, hashSize, digest(blob: blob, type: hashType)))
            }
            return records.isEmpty ? .notPresent : .present(records)
        }

        /// The digest of the complete blob bytes using the blob's own hash type. Unknown types never fall back.
        static func digest(blob: [UInt8], type: UInt8) -> CodeDirectoryDigestStatus {
            switch type {
            case MachOConstants.codeSignatureHashTypeSHA1:
                return .available(CodeDirectoryDigest(algorithm: .sha1, fullBytes: Array(Insecure.SHA1.hash(data: blob))))
            case MachOConstants.codeSignatureHashTypeSHA256:
                return .available(CodeDirectoryDigest(algorithm: .sha256, fullBytes: Array(SHA256.hash(data: blob))))
            case MachOConstants.codeSignatureHashTypeSHA256Truncated:
                // Type 3 stores the full SHA-256; the 20-byte value is derived from it (open row AQ2).
                return .available(CodeDirectoryDigest(algorithm: .sha256Truncated20, fullBytes: Array(SHA256.hash(data: blob))))
            case MachOConstants.codeSignatureHashTypeSHA384:
                return .available(CodeDirectoryDigest(algorithm: .sha384, fullBytes: Array(SHA384.hash(data: blob))))
            default:
                return .unavailable(.unsupportedDigestAlgorithm(type))
            }
        }
    }
}
