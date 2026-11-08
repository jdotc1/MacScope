import Foundation
import CryptoKit
import Darwin

enum EditJournalError: LocalizedError, Equatable {
    case pathRefused(String)
    case notAJournal
    case corrupt(line: Int)
    case identityMismatch
    case baseMismatch
    case lineTooLarge(maximumBytes: Int)
    case claimHistoryTooLarge(maximumBytes: Int)
    case ownedByAnotherWriter
    case staleValidation
    case io(String)

    var errorDescription: String? {
        switch self {
        case .pathRefused(let reason): return "journal-path-refused: \(reason)"
        case .notAJournal: return "journal-not-a-journal"
        case .corrupt(let line): return "journal-corrupt: line \(line)"
        case .identityMismatch: return "journal-identity-mismatch"
        case .baseMismatch: return "journal-base-mismatch"
        case .lineTooLarge(let maximum): return "journal-line-too-large: maximum \(maximum) bytes"
        case .claimHistoryTooLarge(let maximum): return "journal-claim-history-too-large: maximum \(maximum) bytes"
        case .ownedByAnotherWriter: return "journal-owned-by-another-writer"
        case .staleValidation: return "journal-stale-validation"
        case .io(let reason): return "journal-io: \(reason)"
        }
    }
}

struct EditJournalImageIdentity: Codable, Equatable {
    let slot: Int
    let name: String
    let kind: String
    let architecture: String
    let selectedSliceIndex: Int?
    let uuid: String?
    let elfGNUBuildID: String?
    let imageByteCount: Int
    let imageSHA256: String

    static func capture(_ snapshot: WorkspaceSnapshot) -> [Self] {
        snapshot.binaries.sorted { $0.slot < $1.slot }.map { image in
            let bytes = snapshot.analysis(in: image.slot)?.imageBytes ?? Data()
            return Self(slot: image.slot.rawValue, name: image.name, kind: image.kind,
                architecture: image.architecture, selectedSliceIndex: image.selectedSliceIndex,
                uuid: image.metadata.uuid, elfGNUBuildID: image.metadata.elfGNUBuildID,
                imageByteCount: bytes.count, imageSHA256: EditJournalCodec.hex(SHA256.hash(data: bytes)))
        }
    }

    private enum CodingKeys: String, CodingKey {
        case slot, name, kind, architecture, selectedSliceIndex, uuid, elfGNUBuildID, imageByteCount, imageSHA256
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(slot, forKey: .slot)
        try c.encode(name, forKey: .name)
        try c.encode(kind, forKey: .kind)
        try c.encode(architecture, forKey: .architecture)
        try c.encode(selectedSliceIndex, forKey: .selectedSliceIndex)
        try c.encode(uuid, forKey: .uuid)
        try c.encode(elfGNUBuildID, forKey: .elfGNUBuildID)
        try c.encode(imageByteCount, forKey: .imageByteCount)
        try c.encode(imageSHA256, forKey: .imageSHA256)
    }
}

struct EditJournalHeader: Codable {
    var base: [AddressOverrideEntry]
    var format = "macscope-edit-journal"
    var images: [EditJournalImageIdentity]
    var seq: UInt64 = 0
    var version = 1
}

enum EditJournalRecord: Codable {
    case `override`(seq: UInt64, slot: Int, address: UInt64, value: AddressOverride?)
    case slotOverrides(seq: UInt64, slot: Int, entries: [AddressOverrideEntry])
    /// VA3b: ONE line carrying the annotation override change AND its verified-annotation audit
    /// record, so a crash can never leave an accepted edit without its receipt. `slot` is -1 and
    /// `changesOverride` is false for an audit-only (rejected receipt) transaction. Header version
    /// stays 1: a pre-VA3b reader throws on the unknown kind and fails closed.
    case verifiedAnnotation(seq: UInt64, slot: Int, address: UInt64, changesOverride: Bool,
                            value: AddressOverride?, audit: VerifiedAnnotationAuditRecord)
    case calleeClaim(seq: UInt64, event: VACalleeClaimEvent)

    var seq: UInt64 {
        switch self {
        case .override(let seq, _, _, _), .slotOverrides(let seq, _, _),
             .verifiedAnnotation(let seq, _, _, _, _, _): return seq
        case .calleeClaim(let seq, _): return seq
        }
    }

    var slot: Int {
        switch self {
        case .override(_, let slot, _, _), .slotOverrides(_, let slot, _),
             .verifiedAnnotation(_, let slot, _, _, _, _): return slot
        case .calleeClaim: return -1
        }
    }

    private enum CodingKeys: String, CodingKey {
        case seq, kind, slot, address, value, entries, changesOverride, audit, event
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let seq = try c.decode(UInt64.self, forKey: .seq)
        let slot = try c.decode(Int.self, forKey: .slot)
        switch try c.decode(String.self, forKey: .kind) {
        case "override":
            self = .override(seq: seq, slot: slot, address: try c.decode(UInt64.self, forKey: .address),
                             value: try c.decodeIfPresent(AddressOverride.self, forKey: .value))
        case "slotOverrides":
            self = .slotOverrides(seq: seq, slot: slot,
                                 entries: try c.decode([AddressOverrideEntry].self, forKey: .entries))
        case "verifiedAnnotation":
            self = .verifiedAnnotation(
                seq: seq, slot: slot, address: try c.decode(UInt64.self, forKey: .address),
                changesOverride: try c.decode(Bool.self, forKey: .changesOverride),
                value: try c.decodeIfPresent(AddressOverride.self, forKey: .value),
                audit: try c.decode(VerifiedAnnotationAuditRecord.self, forKey: .audit))
        case "calleeClaim":
            guard slot == -1 else {
                throw DecodingError.dataCorruptedError(forKey: .slot, in: c, debugDescription: "claim slot must be -1")
            }
            self = .calleeClaim(seq: seq, event: try c.decode(VACalleeClaimEvent.self, forKey: .event))
        default:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown record kind")
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(seq, forKey: .seq)
        try c.encode(slot, forKey: .slot)
        switch self {
        case .override(_, _, let address, let value):
            try c.encode("override", forKey: .kind)
            try c.encode(address, forKey: .address)
            try c.encodeIfPresent(value, forKey: .value)
        case .slotOverrides(_, _, let entries):
            try c.encode("slotOverrides", forKey: .kind)
            try c.encode(entries, forKey: .entries)
        case .verifiedAnnotation(_, _, let address, let changesOverride, let value, let audit):
            try c.encode("verifiedAnnotation", forKey: .kind)
            try c.encode(address, forKey: .address)
            try c.encode(changesOverride, forKey: .changesOverride)
            try c.encodeIfPresent(value, forKey: .value)
            try c.encode(audit, forKey: .audit)
        case .calleeClaim(_, let event):
            try c.encode("calleeClaim", forKey: .kind)
            try c.encode(event, forKey: .event)
        }
    }
}

struct EditJournalContents {
    let header: EditJournalHeader?
    let records: [EditJournalRecord]
    let completeByteCount: Int
    let tornTail: (offset: Int, length: Int)?
}

struct EditJournalReport {
    let replayed: Int
    let tornTail: (offset: Int, length: Int)?
    let alreadyApplied: Bool
    let created: Bool
    /// VA3b: audit records whose owner differs from this workspace. Their override was replayed
    /// as an ordinary edit; the new owner makes no verified claim about it.
    var unattachedAuditRecords: [UUID] = []
    /// Recovered bytes do not prove that a prior caller received an acknowledgment.
    var priorAcknowledgmentsVerified: Bool { false }
}

enum EditJournalCodec {
    static let maximumLineBytes = 8 * 1_024 * 1_024
    static let maximumClaimHistoryBytes = 24 * 1_024 * 1_024

    static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    /// Conservative sequence width keeps interleaved audit/override records within the budget.
    /// Stop before retaining the next line; no unbounded array of encoded history is built.
    static func validateClaimHistorySize(_ events: [VACalleeClaimEvent]) throws {
        var remaining = maximumClaimHistoryBytes
        for event in events {
            let bytes = try line(EditJournalRecord.calleeClaim(seq: UInt64.max, event: event)).count
            guard bytes <= remaining else {
                throw EditJournalError.claimHistoryTooLarge(maximumBytes: maximumClaimHistoryBytes)
            }
            remaining -= bytes
        }
    }

    static func line<T: Encodable>(_ value: T) throws -> Data {
        let json = try encode(value)
        guard json.count <= maximumLineBytes - 18 else {
            throw EditJournalError.lineTooLarge(maximumBytes: maximumLineBytes)
        }
        let digest = hex(SHA256.hash(data: json).prefix(8))
        var line = Data((digest + " ").utf8)
        line.append(json)
        line.append(10)
        return line
    }

    static func entries(_ map: [ImageAddress: AddressOverride]) -> [AddressOverrideEntry] {
        map.sorted {
            $0.key.slot == $1.key.slot ? $0.key.address < $1.key.address : $0.key.slot < $1.key.slot
        }.map { AddressOverrideEntry(address: $0.key.address, imageSlot: $0.key.slot, override: $0.value) }
    }

    static func map(_ entries: [AddressOverrideEntry], slots: Set<Int>, line: Int,
                    onlySlot: Int? = nil) throws -> [ImageAddress: AddressOverride] {
        var result: [ImageAddress: AddressOverride] = [:]
        for entry in entries {
            let slot = entry.imageSlot.rawValue
            let key = ImageAddress(slot: entry.imageSlot, address: entry.address)
            guard slots.contains(slot), onlySlot == nil || onlySlot == slot,
                  result[key] == nil else { throw EditJournalError.corrupt(line: line) }
            result[key] = entry.override
        }
        return result
    }
}

struct EditJournalReader {
    static func read(_ data: Data) throws -> EditJournalContents {
        guard !data.isEmpty else {
            return .init(header: nil, records: [], completeByteCount: 0, tornTail: nil)
        }
        let pieces = data.split(separator: 10, omittingEmptySubsequences: false)
        let first = Data(pieces[0])
        func payload(_ line: Data) -> Data? {
            guard line.count >= 18, line[line.startIndex + 16] == 32,
                  line.prefix(16).allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
            return Data(line.dropFirst(17))
        }
        guard let firstJSON = payload(first),
              let object = try? JSONSerialization.jsonObject(with: firstJSON) as? [String: Any],
              object.keys.contains("format") else { throw EditJournalError.notAJournal }
        // A recognizable but unterminated header is not a usable journal.
        guard pieces.count > 1 else { throw EditJournalError.corrupt(line: 1) }
        func verified(_ line: Data, number: Int) throws -> Data {
            guard line.count < EditJournalCodec.maximumLineBytes, let json = payload(line),
                  Data(EditJournalCodec.hex(SHA256.hash(data: json).prefix(8)).utf8) == line.prefix(16) else {
                throw EditJournalError.corrupt(line: number)
            }
            return json
        }
        let header: EditJournalHeader
        do { header = try JSONDecoder().decode(EditJournalHeader.self, from: verified(first, number: 1)) }
        catch { throw EditJournalError.corrupt(line: 1) }
        let slots = header.images.map(\.slot)
        guard header.format == "macscope-edit-journal", (header.version == 1 || header.version == 2),
              header.seq == 0,
              slots == slots.sorted(), Set(slots).count == slots.count,
              header.images.allSatisfy({ $0.imageByteCount >= 0 && $0.imageSHA256.utf8.count == 64
                  && $0.imageSHA256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) else {
            throw EditJournalError.corrupt(line: 1)
        }
        let allowed = Set(slots)
        _ = try EditJournalCodec.map(header.base, slots: allowed, line: 1)
        var records: [EditJournalRecord] = []
        var remainingClaimBytes = EditJournalCodec.maximumClaimHistoryBytes
        var claimRecordCount = 0
        var complete = first.count + 1
        // The last segment is empty after a final newline, or is the only torn tail.
        for index in 1..<(pieces.count - 1) {
            let line = Data(pieces[index])
            let record: EditJournalRecord
            do { record = try JSONDecoder().decode(EditJournalRecord.self, from: verified(line, number: index + 1)) }
            catch { throw EditJournalError.corrupt(line: index + 1) }
            var slotAllowed = allowed.contains(record.slot)
            if case .verifiedAnnotation(_, _, _, let changesOverride, _, _) = record, !changesOverride {
                slotAllowed = record.slot == -1
            }
            if case .calleeClaim = record {
                slotAllowed = record.slot == -1 && header.version == 2
                // R2(b): the leaf Core types ignore unknown members, so the reader admits a claim
                // line only if it is exactly the canonical encoding of the value it decodes to.
                guard (try? EditJournalCodec.encode(record)) == (try? verified(line, number: index + 1)) else {
                    throw EditJournalError.corrupt(line: index + 1)
                }
                guard line.count < remainingClaimBytes else {
                    throw EditJournalError.claimHistoryTooLarge(maximumBytes: EditJournalCodec.maximumClaimHistoryBytes)
                }
                remainingClaimBytes -= line.count + 1
                claimRecordCount += 1
                guard claimRecordCount <= VACalleeClaimLimits.maximumEvents else {
                    throw EditJournalError.corrupt(line: index + 1)
                }
            }
            guard record.seq == UInt64(index), slotAllowed else {
                throw EditJournalError.corrupt(line: index + 1)
            }
            if case .verifiedAnnotation(_, _, let address, let changesOverride, let value, _) = record {
                // An override change must name an attached image; audit-only must carry none.
                guard changesOverride || (value == nil && address == 0) else {
                    throw EditJournalError.corrupt(line: index + 1)
                }
            }
            if case .slotOverrides(_, let slot, let entries) = record {
                _ = try EditJournalCodec.map(entries, slots: allowed, line: index + 1, onlySlot: slot)
            }
            records.append(record)
            complete += line.count + 1
        }
        let tailLength = pieces.last!.count
        return .init(header: header, records: records, completeByteCount: complete,
                     tornTail: tailLength == 0 ? nil : (complete, tailLength))
    }
}

// Observed writer state only; this does not establish replay or durability.
enum EditJournalHealth: String, Sendable {
    case disabled, healthy
    case stickyFailed = "sticky-failed"
    case unavailable
}

/// Invocation-local evidence that this writer's corresponding live override changed.
@MainActor
final class JournalMutationWitness {
    @TaskLocal static var current: JournalMutationWitness?
    private let writer: EditJournalWriter?
    private(set) var didApply = false
    init(writer: EditJournalWriter?) { self.writer = writer }
    func record(_ candidate: EditJournalWriter?) {
        guard let writer, let candidate, writer === candidate else { return }
        didApply = true
    }
}

final class EditJournalWriter {
    let url: URL
    private var descriptor: Int32
    private var headerVersion: Int
    private(set) var imageIdentities: [EditJournalImageIdentity]
    private(set) var sequence: UInt64
    var appendedSequence: UInt64 { sequence }
    private(set) var lastAppendedRecord: EditJournalRecord?
    private(set) var failure: String?
    var appendHook: ((Data) throws -> Void)?
    var beforeAppendSyncForTesting: ((Int32) throws -> Void)?
    var rotateHook: ((_ step: String) throws -> Void)?

    var observedHealth: EditJournalHealth {
        if failure != nil { return .stickyFailed }
        return descriptor >= 0 ? .healthy : .unavailable
    }

    /// `expectedContents` are the exact bytes the caller validated. After the exclusive advisory
    /// lock is held, the writer re-reads the file from its own descriptor and refuses on any
    /// difference before it truncates a torn tail or writes a header. The default (empty) is the
    /// right value for a journal the caller has just seen absent.
    ///
    /// `openHookForTesting`: Test-only seam. Runs after the lock is held and before the path
    /// identity check, so a test can detach the opened inode deterministically. Production
    /// callers leave it nil.
    init(url: URL, header: EditJournalHeader, sequence: UInt64, createHeader: Bool,
         truncateTo: Int? = nil, expectedContents: Data = Data(),
         openHookForTesting: ((String) throws -> Void)? = nil) throws {
        self.url = url
        self.sequence = sequence
        self.headerVersion = header.version
        self.imageIdentities = header.images
        descriptor = Darwin.open(url.path, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw Self.systemError("open") }
        do {
            try Self.lockExclusively(descriptor)
            try openHookForTesting?(url.path)
            try Self.requireCurrentRegularFile(descriptor, at: url)
            guard try Self.readAll(descriptor) == expectedContents else {
                throw EditJournalError.staleValidation
            }
            if let truncateTo {
                guard Darwin.ftruncate(descriptor, off_t(truncateTo)) == 0 else {
                    throw Self.systemError("truncate")
                }
                try Self.sync(descriptor)
            }
            if createHeader {
                try Self.writeLine(EditJournalCodec.line(header), to: descriptor)
                try Self.syncDirectory(url.deletingLastPathComponent())
            }
        } catch {
            Darwin.close(descriptor)
            descriptor = -1
            throw error
        }
    }

    /// Refuses unless `url` currently names, as a regular file and not through a final symlink,
    /// the same inode this writer holds open. Detects observed replacement only; the check and
    /// the following use are not atomic.
    private static func requireCurrentRegularFile(_ descriptor: Int32, at url: URL) throws {
        var opened = stat(), named = stat()
        guard descriptor >= 0,
              Darwin.fstat(descriptor, &opened) == 0,
              Darwin.lstat(url.path, &named) == 0,
              opened.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              named.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              opened.st_dev == named.st_dev, opened.st_ino == named.st_ino else {
            throw EditJournalError.io("journal path no longer names this writer")
        }
    }

    /// Nonblocking exclusive advisory lock on the inode behind `descriptor`. It covers hard-link
    /// aliases, and is released when the descriptor closes. It binds cooperating writers only.
    static func lockExclusively(_ descriptor: Int32) throws {
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            if errno == EWOULDBLOCK { throw EditJournalError.ownedByAnotherWriter }
            throw systemError("flock")
        }
    }

    static func readAll(_ descriptor: Int32) throws -> Data {
        var info = stat()
        guard Darwin.fstat(descriptor, &info) == 0 else { throw systemError("fstat") }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        var offset: off_t = 0
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress!, $0.count, offset) }
            if count < 0 {
                if errno == EINTR { continue }
                throw systemError("read")
            }
            if count == 0 { break }
            result.append(contentsOf: buffer[0..<count])
            offset += off_t(count)
        }
        return result
    }

    deinit { if descriptor >= 0 { Darwin.close(descriptor) } }

    func close() {
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
    }

    static func systemError(_ operation: String) -> EditJournalError {
        let code = errno
        return .io("\(operation): \(String(cString: strerror(code)))")
    }

    static func sync(_ descriptor: Int32) throws {
        while Darwin.fsync(descriptor) != 0 {
            if errno == EINTR { continue }
            throw systemError("fsync")
        }
    }

    static func syncDirectory(_ url: URL) throws {
        let fd = Darwin.open(url.path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw systemError("open directory") }
        defer { Darwin.close(fd) }
        try sync(fd)
    }

    static func writeLine(_ line: Data, to descriptor: Int32,
                          beforeSync: ((Int32) throws -> Void)? = nil) throws {
        guard descriptor >= 0 else { throw EditJournalError.io("writer closed") }
        let count: Int = line.withUnsafeBytes { bytes in
            while true {
                let result = Darwin.write(descriptor, bytes.baseAddress!, bytes.count)
                if result < 0 && errno == EINTR { continue }
                return result
            }
        }
        guard count >= 0 else { throw systemError("write") }
        guard count == line.count else { throw EditJournalError.io("short write: \(count) of \(line.count) bytes") }
        try beforeSync?(descriptor)
        try sync(descriptor)
    }

    private func append(_ make: (UInt64) -> EditJournalRecord) {
        guard failure == nil else { return }
        do {
            guard sequence < UInt64.max else { throw EditJournalError.io("sequence exhausted") }
            let next = sequence + 1
            let record = make(next)
            let line = try EditJournalCodec.line(record)
            try appendHook?(line)
            try Self.requireCurrentRegularFile(descriptor, at: url)
            try Self.writeLine(line, to: descriptor, beforeSync: beforeAppendSyncForTesting)
            try Self.requireCurrentRegularFile(descriptor, at: url)
            sequence = next
            lastAppendedRecord = record
        } catch { failure = error.localizedDescription }
    }

    func appendOverride(_ key: ImageAddress, _ value: AddressOverride?) {
        append { .override(seq: $0, slot: key.slot.rawValue, address: key.address, value: value) }
    }

    /// Appends the single combined verified-annotation line. The caller decides success from
    /// `observedHealth` and `appendedSequence`: a failed append is always uncertain because the
    /// writer cannot tell "not written" from "written, fsync failed".
    func appendVerifiedAnnotation(slot: Int, address: UInt64, changesOverride: Bool,
                                  value: AddressOverride?, audit: VerifiedAnnotationAuditRecord) {
        append {
            .verifiedAnnotation(seq: $0, slot: slot, address: address, changesOverride: changesOverride,
                                value: value, audit: audit)
        }
    }

    /// Reading complete records does not prove an earlier writer synchronized them. The
    /// caller invokes this only for recovered claims, before reporting journal durability.
    /// Like the existing journal owner, this assumes no concurrent writer for the same path.
    func synchronizeRecoveredCalleeClaims() -> Bool {
        guard failure == nil else { return false }
        do {
            guard observedHealth == .healthy else { throw EditJournalError.io("writer closed") }
            try Self.sync(descriptor)
            // A prior replacement may have failed its directory sync after rename.
            try Self.syncDirectory(url.deletingLastPathComponent())
            return true
        } catch {
            failure = "recovery sync: \(error.localizedDescription)"
            return false
        }
    }

    /// `priorEvents` is the full validated live ledger prefix, not merely journal-local events.
    /// A v1 journal is upgraded atomically before any claim can be acknowledged. Its original
    /// base and all override/audit records survive; unsaved edits must never become a new base.
    /// A successful upgrade can advance `sequence` by more than one. Inspect health and the
    /// last record's event, rather than assuming a one-record increment.
    func appendCalleeClaim(_ event: VACalleeClaimEvent, priorEvents: [VACalleeClaimEvent]) {
        guard failure == nil else { return }
        do {
            guard descriptor >= 0 else { throw EditJournalError.io("writer closed") }
            _ = try CalleeClaimLedger(events: priorEvents + [event])
            try EditJournalCodec.validateClaimHistorySize(priorEvents + [event])
            if headerVersion == 1 {
                let original = try Data(contentsOf: url)
                let contents = try EditJournalReader.read(original)
                guard var header = contents.header, header.version == 1,
                      contents.tornTail == nil, (contents.records.last?.seq ?? 0) == sequence,
                      let newline = original.firstIndex(of: 10) else {
                    throw EditJournalError.io("journal changed before claim upgrade")
                }
                header.version = 2
                var records = contents.records
                for item in priorEvents + [event] {
                    records.append(.calleeClaim(seq: UInt64(records.count + 1), event: item))
                }
                try appendHook?(EditJournalCodec.line(records[records.count - 1]))
                try replace(header: header, records: records,
                            retainedBody: Data(original.suffix(from: newline + 1)),
                            retainedRecordCount: contents.records.count)
            } else {
                guard headerVersion == 2 else { throw EditJournalError.corrupt(line: 1) }
                append { .calleeClaim(seq: $0, event: event) }
            }
        } catch { failure = error.localizedDescription }
    }

    func appendSlotOverrides(_ slot: ImageSlot, _ overrides: [ImageAddress: AddressOverride]) {
        append {
            .slotOverrides(seq: $0, slot: slot.rawValue,
                entries: EditJournalCodec.entries(overrides.filter { $0.key.slot == slot }))
        }
    }

    func rotate(images: [EditJournalImageIdentity], base: [ImageAddress: AddressOverride],
                calleeClaims: [VACalleeClaimEvent] = []) {
        guard failure == nil else { return }
        do {
            _ = try CalleeClaimLedger(events: calleeClaims)
            try EditJournalCodec.validateClaimHistorySize(calleeClaims)
            var header = EditJournalHeader(base: EditJournalCodec.entries(base), images: images)
            header.version = calleeClaims.isEmpty ? 1 : 2
            let records = calleeClaims.enumerated().map {
                EditJournalRecord.calleeClaim(seq: UInt64($0.offset + 1), event: $0.element)
            }
            try replace(header: header, records: records)
        } catch { failure = "rotation: \(error.localizedDescription)" }
    }

    /// Preflight every line before opening the temporary file. A failed replacement is sticky;
    /// the old file remains available either at the live path or in its retained hard link.
    private func replace(header: EditJournalHeader, records: [EditJournalRecord],
                         retainedBody: Data = Data(), retainedRecordCount: Int = 0) throws {
            let headerLine = try EditJournalCodec.line(header)
            let lines = try records.dropFirst(retainedRecordCount).map { try EditJournalCodec.line($0) }
            try rotateHook?("header")
            // Exclusive create: an existing `.rotating` (or any temp) is evidence and is never
            // truncated. The new generation is locked before its header is written, and the same
            // descriptor is kept across rename and directory sync.
            var tempSuffix = 0
            var temporary = url.path + ".rotating"
            var fd: Int32 = -1
            while true {
                fd = Darwin.open(temporary, O_RDWR | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o600))
                if fd >= 0 { break }
                guard errno == EEXIST else { throw Self.systemError("open rotation") }
                guard tempSuffix < Int.max else { throw EditJournalError.io("rotation suffix exhausted") }
                tempSuffix += 1
                temporary = url.path + ".rotating.\(tempSuffix)"
            }
            var adopted = false
            defer { if !adopted { Darwin.close(fd) } }
            try Self.lockExclusively(fd)
            try Self.writeLine(headerLine, to: fd)
            if !retainedBody.isEmpty { try Self.writeLine(retainedBody, to: fd) }
            for line in lines {
                try Self.writeLine(line, to: fd, beforeSync: beforeAppendSyncForTesting)
            }

            try rotateHook?("retire")
            try Self.requireCurrentRegularFile(descriptor, at: url)
            var suffix = 1
            while Darwin.link(url.path, url.path + ".retired.\(suffix)") != 0 {
                guard errno == EEXIST else { throw Self.systemError("retire") }
                guard suffix < Int.max else { throw EditJournalError.io("retired suffix exhausted") }
                suffix += 1
            }
            try rotateHook?("rename")
            try Self.requireCurrentRegularFile(descriptor, at: url)
            guard Darwin.rename(temporary, url.path) == 0 else { throw Self.systemError("rename rotation") }
            try Self.syncDirectory(url.deletingLastPathComponent())
            Darwin.close(descriptor)
            descriptor = fd
            adopted = true
            headerVersion = header.version
            imageIdentities = header.images
            sequence = records.last?.seq ?? 0
            lastAppendedRecord = records.last
    }
}
