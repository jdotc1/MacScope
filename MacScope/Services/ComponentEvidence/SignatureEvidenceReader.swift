// Original to this item (AR2). Descriptor-bound capture of raw code-signature evidence, adapted in structure
// (bounded positional reads, one streaming hash pass, per-slice attribution) from the EntitlementLens bounded
// SuperBlob capture through the AIRS component evidence core at donor commit
// fa5a2f3128da9134969055cebea145e2ca144214. MacScope adds the shared read ledger, the fat admission checks, the
// CodeDirectory records, the typed PARTIAL completion and the all-or-nothing publication rule.
// The reader never stores a descriptor, reopens a path, loads or executes the image, or validates trust.

import CryptoKit
import Darwin
import Foundation

extension ComponentEvidence {
    /// Where one examined slice keeps its signature, in container-relative and slice-relative terms.
    struct SignatureSliceLocation: Sendable, Hashable {
        let key: SignatureSliceKey
        let command: SignatureCommandLocation
    }

    enum SignatureEvidenceReader {
        private static let fatMagics: Set<UInt32> = [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]

        private static func number(_ bytes: [UInt8], _ start: Int, _ width: Int = 4, little: Bool) -> UInt64 {
            (0..<width).reduce(UInt64(0)) { $0 | UInt64(bytes[start + $1]) << UInt64((little ? $1 : width - 1 - $1) * 8) }
        }

        /// The adapter for a held descriptor. The fault seam of the AR1 descriptor operations stays in force.
        static func descriptorRead(_ descriptor: Int32, ops: DescriptorOps, range: PathRange) -> (UInt64, Int) throws -> [UInt8] {
            { offset, count in try ops.read(descriptor, offset: offset, count: count, range) }
        }

        private struct Pending {
            var key: SignatureSliceKey
            var supported: Bool
            var command: SignatureCommandLocation?
            var refusal: SignatureRefusal?
            var budget: CaptureLimit?
            var absent = false
        }

        /// Captures once. Global defects throw and publish nothing. `ledger` is the caller's shared header ledger; it is
        /// charged for every header read and never reset. `revalidate` must throw on any change of the held image.
        static func capture(size: UInt64, limits: SignatureEvidenceLimits = SignatureEvidenceLimits(), ledger: inout ReadLedger,
                            isCancelled: () -> Bool = { Task.isCancelled }, revalidate: () throws -> Void = {},
                            read: (UInt64, Int) throws -> [UInt8]) throws -> SignatureEvidence {
            try limits.validate()
            if isCancelled() { throw SignatureCaptureError.cancelled }
            try revalidate()
            guard size > 0 else { throw SignatureCaptureError.invalidContainer(.emptyImage) }
            var headerCharged = 0, headerRead = 0, signatureCharged = 0, signatureRead = 0
            var readRanges: [ByteRange] = []
            var losses: [CaptureLoss] = []

            func fetch(_ offset: UInt64, _ count: Int) throws -> [UInt8] {
                if isCancelled() { throw SignatureCaptureError.cancelled }
                let range = ByteRange(uncheckedStart: offset, end: offset + UInt64(count))
                do {
                    let bytes = try read(offset, count)
                    guard bytes.count == count else { throw SignatureCaptureError.shortRead(range: range, expected: count, actual: bytes.count) }
                    return bytes
                } catch let error as SignatureCaptureError {
                    throw error
                } catch EvidenceError.io(_, let code, _) {
                    throw SignatureCaptureError.unavailable(.read, errno: code, range: range)
                } catch EvidenceError.shortRead(_, let expected, let actual) {
                    throw SignatureCaptureError.shortRead(range: range, expected: expected, actual: actual)
                } catch EvidenceError.cancelled {
                    throw SignatureCaptureError.cancelled
                } catch is CancellationError {
                    throw SignatureCaptureError.cancelled
                } catch {
                    throw SignatureCaptureError.unavailable(.read, errno: nil, range: range)
                }
            }
            /// Header read. Nil means the header allowance is spent.
            func header(_ offset: UInt64, _ count: Int) throws -> [UInt8]? {
                guard headerCharged + count <= limits.headerBytes, ledger.charge(count) else { return nil }
                headerCharged += count
                let bytes = try fetch(offset, count)
                headerRead += count
                readRanges.append(ByteRange(uncheckedStart: offset, end: offset + UInt64(count)))
                return bytes
            }
            func snapshot(hashed: UInt64) -> SignatureReadLedgerSnapshot {
                SignatureReadLedgerSnapshot(headerBytesCharged: headerCharged, headerBytesRead: headerRead,
                    signatureBytesCharged: signatureCharged, signatureBytesRead: signatureRead, bytesHashed: hashed,
                    sharedLedgerUsedAtEnd: ledger.used)
            }
            /// No slice evidence at all: a preflight or structure cap reached before any slice could be attributed.
            func refusedAll(_ limit: CaptureLimit, attempted: Int?, basis: ObservationBasis, declaredSlices: Int? = nil,
                            mismatches: [KnownMismatch]) throws -> SignatureEvidence {
                losses.append(CaptureLoss(limit: limit, configured: limitValue(limit, limits), attempted: attempted, range: nil, basis: basis))
                let partial = try PartialCapture(losses: losses, knownMismatches: mismatches,
                    hashedContainerRange: ByteRange(uncheckedStart: 0, end: 0), successfullyReadRanges: readRanges,
                    bytesHashed: 0, observedOmittedSliceCount: nil, observedOmittedIndexedBlobCount: nil)
                try revalidate()
                if isCancelled() { throw SignatureCaptureError.cancelled }
                return try SignatureEvidence(containerSize: size, containerSHA256: .unavailable(.capReached(limit)), slices: [],
                    completion: .partial(partial), declaredSliceCount: declaredSlices, ledger: snapshot(hashed: 0))
            }

            if size > UInt64(limits.containerHashBytes) {
                return try refusedAll(.containerHashBytes, attempted: Int(clamping: size), basis: .notApplicable,
                                      mismatches: [.limitReached(.containerHashBytes)])
            }

            // MARK: Layout
            guard size >= 4 else { throw SignatureCaptureError.invalidContainer(.unsupportedMagic) }
            guard let first = try header(0, Int(min(size, 8))) else {
                return try refusedAll(.headerBytes, attempted: nil, basis: .notApplicable, mismatches: [.limitReached(.headerBytes)])
            }
            let magic = UInt32(number(first, 0, little: false))
            var entries: [(cpu: UInt32, subtype: UInt32, offset: UInt64, size: UInt64)] = []
            let universal = fatMagics.contains(magic)
            if universal {
                guard first.count == 8 else { throw SignatureCaptureError.invalidContainer(.invalidFatLayout) }
                let little = [0xbebafeca, 0xbfbafeca].contains(magic), wide = [0xcafebabf, 0xbfbafeca].contains(magic)
                let count = Int(number(first, 4, little: little)), stride = wide ? 32 : 20
                guard count > 0 else { throw SignatureCaptureError.invalidContainer(.invalidFatLayout) }
                if count > limits.slices {
                    return try refusedAll(.slices, attempted: count, basis: .declaredHeaderDomain, declaredSlices: count,
                                          mismatches: [.declaredSliceCountAboveCap(declared: count), .limitReached(.slices)])
                }
                let tableEnd = UInt64(8 + count * stride)
                guard tableEnd <= size else { throw SignatureCaptureError.invalidContainer(.invalidFatLayout) }
                guard let table = try header(8, count * stride) else {
                    return try refusedAll(.headerBytes, attempted: nil, basis: .notApplicable, mismatches: [.limitReached(.headerBytes)])
                }
                var seen = Set<UInt64>()
                for index in 0..<count {
                    let base = index * stride
                    let cpu = UInt32(number(table, base, little: little)), subtype = UInt32(number(table, base + 4, little: little))
                    let offset = number(table, base + 8, wide ? 8 : 4, little: little)
                    let length = number(table, base + (wide ? 16 : 12), wide ? 8 : 4, little: little)
                    let alignment = number(table, base + (wide ? 24 : 16), little: little)
                    guard length > 0, offset >= tableEnd, offset <= size, length <= size - offset, alignment <= 15,
                          offset & ((UInt64(1) << alignment) - 1) == 0 else { throw SignatureCaptureError.invalidContainer(.invalidFatLayout) }
                    guard seen.insert(UInt64(cpu) << 32 | UInt64(subtype & 0x00ffffff)).inserted else {
                        throw SignatureCaptureError.invalidContainer(.invalidFatLayout)
                    }
                    if wide, number(table, base + 28, little: little) != 0 { throw SignatureCaptureError.invalidContainer(.invalidFatLayout) }
                    entries.append((cpu, subtype, offset, length))
                }
                let ordered = entries.sorted { $0.offset < $1.offset }
                for (previous, next) in zip(ordered, ordered.dropFirst()) where next.offset < previous.offset + previous.size {
                    throw SignatureCaptureError.invalidContainer(.overlappingFatSlices)
                }
            } else {
                entries = [(0, 0, 0, size)]
            }

            var pending: [Pending] = []
            for (index, entry) in entries.enumerated() {
                let headerCount = Int(min(entry.size, 32))
                guard headerCount >= 12 else { throw SignatureCaptureError.invalidContainer(.malformedHeader) }
                guard let bytes = try header(entry.offset, headerCount) else {
                    return try refusedAll(.headerBytes, attempted: nil, basis: .notApplicable, mismatches: [.limitReached(.headerBytes)])
                }
                let sliceMagic = UInt32(number(bytes, 0, little: false))
                let known: [UInt32: (little: Bool, wide: Bool)] = [
                    0xcffaedfe: (true, true), 0xfeedfacf: (false, true), 0xcefaedfe: (true, false), 0xfeedface: (false, false)]
                guard let layout = known[sliceMagic] else { throw SignatureCaptureError.invalidContainer(.unsupportedMagic) }
                let cpu = UInt32(number(bytes, 4, little: layout.little)), subtype = UInt32(number(bytes, 8, little: layout.little))
                if universal, cpu != entry.cpu || subtype != entry.subtype {
                    throw SignatureCaptureError.invalidContainer(.fatSliceIdentityMismatch)
                }
                let key = SignatureSliceKey(index: index, cpuType: cpu, cpuSubtype: subtype, headerMagic: sliceMagic,
                                            sliceOffset: entry.offset, sliceSize: entry.size)
                let examined = sliceMagic == 0xcffaedfe && cpu == 0x0100000c && [0, 1, 2].contains(subtype & 0x00ffffff)
                guard examined else {
                    pending.append(Pending(key: key, supported: false))
                    continue
                }
                guard bytes.count == 32 else { throw SignatureCaptureError.invalidContainer(.malformedHeader) }
                let commandCount = Int(number(bytes, 16, little: true)), commandBytes = Int(number(bytes, 20, little: true))
                guard commandCount <= commandBytes / 8, UInt64(32 + commandBytes) <= entry.size else {
                    throw SignatureCaptureError.invalidContainer(.malformedLoadCommands)
                }
                var item = Pending(key: key, supported: true)
                if commandCount == 0 {
                    item.absent = true
                } else if commandCount > limits.loadCommands {
                    item.budget = .loadCommands
                    losses.append(CaptureLoss(limit: .loadCommands, configured: limits.loadCommands, attempted: commandCount,
                                              range: nil, basis: .declaredHeaderDomain))
                } else if let commands = try header(entry.offset + 32, commandBytes) {
                    let located = try BoundedSignatureParser.locateSignatureCommand(commands: commands, commandCount: commandCount,
                                                                                    headerSize: 32, sliceSize: entry.size)
                    item.command = located.location
                    item.refusal = located.refusal
                    item.absent = located.location == nil && located.refusal == nil
                } else {
                    item.budget = .headerBytes
                    losses.append(CaptureLoss(limit: .headerBytes, configured: limits.headerBytes, attempted: commandBytes,
                        range: try ByteRange(start: entry.offset + 32, length: UInt64(commandBytes)), basis: .notApplicable))
                }
                pending.append(item)
            }

            // MARK: One hash pass
            var containerHasher = SHA256()
            var sliceHashers = pending.map { _ in SHA256() }
            var position: UInt64 = 0
            while position < size {
                let count = Int(min(UInt64(limits.hashChunk), size - position))
                let chunk = try fetch(position, count)
                containerHasher.update(data: chunk)
                let chunkEnd = position + UInt64(count)
                for (index, item) in pending.enumerated() {
                    let start = max(position, item.key.sliceOffset), end = min(chunkEnd, item.key.sliceOffset + item.key.sliceSize)
                    if start < end { sliceHashers[index].update(data: chunk[Int(start - position)..<Int(end - position)]) }
                }
                position = chunkEnd
            }
            readRanges.append(ByteRange(uncheckedStart: 0, end: size))
            let containerDigest = DigestObservation.complete(algorithm: .sha256, bytes: Array(containerHasher.finalize()),
                                                              source: ByteRange(uncheckedStart: 0, end: size))

            // MARK: Signatures, in original slice-index order
            var slices: [SignatureSliceEvidence] = []
            var retainedTotal = 0
            for (index, item) in pending.enumerated() {
                if isCancelled() { throw SignatureCaptureError.cancelled }
                let key = item.key
                let sliceDigest = DigestObservation.complete(algorithm: .sha256, bytes: Array(sliceHashers[index].finalize()),
                    source: ByteRange(uncheckedStart: key.sliceOffset, end: key.sliceOffset + key.sliceSize))
                func unavailable(_ state: SignatureEvidenceState, _ problem: SignatureEvidenceProblem) throws -> SignatureSliceEvidence {
                    try SignatureSliceEvidence(key: key, state: state, sliceSHA256: sliceDigest, signature: .unavailable(problem),
                        slots: .unavailable(problem), entitlementsXML: .unavailable(problem), entitlementsDER: .unavailable(problem),
                        codeDirectories: .unavailable(problem))
                }
                if !item.supported {
                    slices.append(try unavailable(.unexamined(.unsupportedArchitecture), .unsupportedArchitecture)); continue
                }
                if let limit = item.budget { slices.append(try unavailable(.budgetExceeded(limit), .capReached(limit))); continue }
                if let refusal = item.refusal { slices.append(try unavailable(.malformed(refusal), .structureRefused(refusal))); continue }
                guard let command = item.command else {
                    slices.append(try SignatureSliceEvidence(key: key, state: .signatureAbsent, sliceSHA256: sliceDigest,
                        signature: .notPresent, slots: .notPresent, entitlementsXML: .notPresent, entitlementsDER: .notPresent,
                        codeDirectories: .notPresent))
                    continue
                }
                let regionRange = try ByteRange(start: key.sliceOffset + UInt64(command.offset), length: UInt64(command.size))
                let requested = Int(command.size)
                if requested > limits.signatureBytes {
                    losses.append(CaptureLoss(limit: .signatureBytes, configured: limits.signatureBytes, attempted: requested,
                                              range: regionRange, basis: .notApplicable))
                    slices.append(try unavailable(.budgetExceeded(.signatureBytes), .capReached(.signatureBytes))); continue
                }
                if requested > limits.totalSignatureBytes - retainedTotal {
                    losses.append(CaptureLoss(limit: .totalSignatureBytes, configured: limits.totalSignatureBytes, attempted: requested,
                                              range: regionRange, basis: .notApplicable))
                    slices.append(try unavailable(.budgetExceeded(.totalSignatureBytes), .capReached(.totalSignatureBytes))); continue
                }
                signatureCharged += requested
                let region = try fetch(regionRange.start, requested)
                signatureRead += requested
                retainedTotal += requested
                readRanges.append(regionRange)
                let outcome = try BoundedSignatureParser(limits: limits).parse(region: region)
                var declared: UInt32?
                var trailing = 0
                if case .parsed(let parsed) = outcome { declared = parsed.declaredLength; trailing = parsed.trailingByteCount }
                let regionEvidence = SignatureRegionEvidence(bytes: region, sha256: Array(SHA256.hash(data: region)),
                    sliceRelativeOffset: UInt64(command.offset), containerOffset: regionRange.start, declaredLength: declared,
                    trailingByteCount: trailing)
                func withRegion(_ state: SignatureEvidenceState, _ problem: SignatureEvidenceProblem) throws -> SignatureSliceEvidence {
                    try SignatureSliceEvidence(key: key, state: state, sliceSHA256: sliceDigest, signature: .present(regionEvidence),
                        slots: .unavailable(problem), entitlementsXML: .unavailable(problem), entitlementsDER: .unavailable(problem),
                        codeDirectories: .unavailable(problem))
                }
                switch outcome {
                case .refused(let refusal):
                    slices.append(try withRegion(.malformed(refusal), .structureRefused(refusal)))
                case .capped(let limit, let declaredCount):
                    losses.append(CaptureLoss(limit: limit, configured: limitValue(limit, limits), attempted: declaredCount,
                                              range: regionRange, basis: .declaredHeaderDomain))
                    slices.append(try withRegion(.budgetExceeded(limit), .capReached(limit)))
                case .parsed(let parsed):
                    func blob(_ slotType: UInt32) throws -> EvidencePresence<SignatureBlobEvidence> {
                        guard let slot = parsed.slots.first(where: { $0.slot == slotType }) else { return .notPresent }
                        let bytes = Array(region[Int(slot.offset)..<(Int(slot.offset) + Int(slot.length))])
                        return .present(try SignatureBlobEvidence(type: slot.slot, magic: slot.magic, bytes: bytes,
                            sha256: Array(SHA256.hash(data: bytes)), containerOffset: regionRange.start + UInt64(slot.offset),
                            sliceRelativeOffset: UInt64(command.offset) + UInt64(slot.offset)))
                    }
                    let xml = try blob(MachOConstants.codeSignatureSlotEntitlements)
                    let der = try blob(MachOConstants.codeSignatureSlotDerEntitlements)
                    let state: SignatureEvidenceState = xml.value != nil || der.value != nil ? .collected : .entitlementsAbsent
                    slices.append(try SignatureSliceEvidence(key: key, state: state, sliceSHA256: sliceDigest,
                        signature: .present(regionEvidence), slots: .present(parsed.slots), entitlementsXML: xml,
                        entitlementsDER: der, codeDirectories: CodeDirectoryReader.read(slots: parsed.slots, region: region)))
                }
            }

            try revalidate()
            if isCancelled() { throw SignatureCaptureError.cancelled }
            let completion: CaptureCompletion
            if losses.isEmpty {
                completion = .complete
            } else {
                let omittedSlices = slices.filter { if case .budgetExceeded = $0.state { true } else { false } }.count
                completion = .partial(try PartialCapture(losses: losses, knownMismatches: Array(Set(losses.map(\.limit))).sorted { $0.rawValue < $1.rawValue }
                    .map { .limitReached($0) }, hashedContainerRange: ByteRange(uncheckedStart: 0, end: size), successfullyReadRanges: readRanges,
                    bytesHashed: size, observedOmittedSliceCount: omittedSlices,
                    observedOmittedIndexedBlobCount: nil))
            }
            return try SignatureEvidence(containerSize: size, containerSHA256: containerDigest, slices: slices, completion: completion,
                                         declaredSliceCount: nil, ledger: snapshot(hashed: size))
        }

        private static func limitValue(_ limit: CaptureLimit, _ limits: SignatureEvidenceLimits) -> Int {
            switch limit {
            case .containerHashBytes: limits.containerHashBytes
            case .headerBytes: limits.headerBytes
            case .loadCommands: limits.loadCommands
            case .slices: limits.slices
            case .signatureBytes: limits.signatureBytes
            case .totalSignatureBytes: limits.totalSignatureBytes
            case .slots: limits.slots
            }
        }
    }
}
