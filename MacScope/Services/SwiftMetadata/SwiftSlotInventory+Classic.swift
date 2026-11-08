import Foundation

extension SwiftSlotInventory {
    /// R-Q8: at most this many recorded events per image. Hitting it makes the scope incomplete.
    static let maxEvents = 1_000_000
}

/// FX-SLOT slice B: decodes every write of the classic `LC_DYLD_INFO(_ONLY)` opcode streams (rebase,
/// bind, weak bind, lazy bind) into inventory events. Unlike `MachODyldInfoFixups` (whose dictionaries
/// stay byte-identical for other consumers) nothing is dropped: a bind of any shape, a narrow write, an
/// unresolved rebase and a duplicate are all recorded, and any stream the engine cannot fully decode
/// returns a refusal reason so the caller withholds the whole image (R-Q3).
enum ClassicSlotInventoryProducer {
    struct Streams {
        var rebase: Range<Int>
        var bind: Range<Int>
        var weakBind: Range<Int>
        var lazyBind: Range<Int>
    }

    private static let pointerMask: UInt64 = 0x0000_ffff_ffff_ffff

    private enum StreamKind {
        case rebase, bind, weakBind, lazyBind
        /// Lazy streams use DONE as an entry separator; the others end at DONE.
        var doneTerminates: Bool { self != .lazyBind }
    }

    /// Returns nil when every stream decoded completely, else the first refusal reason.
    static func decode(data: Data, streams: Streams, segments: [MachOSegment],
                       into builder: inout SwiftSlotInventory.Builder) -> SwiftSlotInventory.Reason? {
        let all: [(StreamKind, Range<Int>)] = [
            (.rebase, streams.rebase), (.bind, streams.bind),
            (.weakBind, streams.weakBind), (.lazyBind, streams.lazyBind),
        ]
        var firstFailure: SwiftSlotInventory.Reason?
        for (kind, range) in all {
            if let failure = decodeStream(kind, data: data, range: range, segments: segments, into: &builder),
               firstFailure == nil {
                firstFailure = failure
            }
        }
        return firstFailure
    }

    private struct Reader {
        let data: Data
        var cursor: Int
        let end: Int
        var failure: SwiftSlotInventory.Reason?

        var atEnd: Bool { cursor >= end }

        mutating func byte() -> UInt8? {
            guard cursor < end else { failure = failure ?? .truncated; return nil }
            defer { cursor += 1 }
            return data[data.startIndex + cursor]
        }

        mutating func uleb() -> UInt64? {
            var value: UInt64 = 0
            var shift: UInt64 = 0
            while let b = byte() {
                let payload = UInt64(b & 0x7f)
                if shift >= 64 {
                    if payload != 0 { failure = .malformedInventory; return nil }
                } else {
                    if shift > 57, payload >> (64 - shift) != 0 { failure = .malformedInventory; return nil }
                    value |= payload << shift
                }
                if b & 0x80 == 0 { return value }
                shift += 7
            }
            return nil
        }

        mutating func sleb() -> Int64? {
            var value: Int64 = 0
            var shift: Int64 = 0
            while let b = byte() {
                if shift < 64 { value |= Int64(b & 0x7f) << shift }
                shift += 7
                if b & 0x80 == 0 {
                    if shift < 64, b & 0x40 != 0 { value |= -(Int64(1) << shift) }
                    return value
                }
                if shift > 70 { failure = .malformedInventory; return nil }
            }
            return nil
        }

        mutating func skipCString() -> Bool {
            while let b = byte() { if b == 0 { return true } }
            return false
        }

        func restIsZero() -> Bool {
            var i = cursor
            while i < end {
                if data[data.startIndex + i] != 0 { return false }
                i += 1
            }
            return true
        }
    }

    private struct Cursor {
        var segment = 0
        var segmentSet = false
        var offset: UInt64 = 0
    }

    private static func decodeStream(_ kind: StreamKind, data: Data, range: Range<Int>, segments: [MachOSegment],
                                     into builder: inout SwiftSlotInventory.Builder) -> SwiftSlotInventory.Reason? {
        if range.isEmpty { return nil }
        guard range.lowerBound >= 0, range.upperBound <= data.count else { return .truncated }
        var r = Reader(data: data, cursor: range.lowerBound, end: range.upperBound)
        var at = Cursor()
        var type: UInt64 = kind == .lazyBind ? 1 : 0

        /// Records one write at the current position. Returns a refusal reason, or nil on success.
        func write() -> SwiftSlotInventory.Reason? {
            guard builder.eventCount < SwiftSlotInventory.maxEvents else { return .budget }
            guard at.segmentSet, at.segment < segments.count else { return .malformedInventory }
            let seg = segments[at.segment]
            let (va, overflow) = seg.vmAddress.addingReportingOverflow(at.offset)
            guard !overflow else { return .malformedInventory }
            switch (kind, type) {
            case (.rebase, 1):
                guard at.offset <= seg.vmSize, seg.vmSize - at.offset >= 8 else { return .malformedInventory }
                if let word = pointer(data: data, segment: seg, offset: at.offset) {
                    if word & ~pointerMask != 0 {
                        // Bits 48-63 are set: the stored word is not a plain unslid pointer, so the masked value
                        // is not authoritative. `.occupied(.nonPointer)` makes word(atSlot:) non-authoritative.
                        builder.occupy(va, .nonPointer)
                    } else {
                        builder.rebase(va, target: word)
                    }
                } else {
                    builder.occupy(va, .unresolvedRebase)
                }
            case (.rebase, 2), (.rebase, 3), (_, 2), (_, 3):
                guard at.offset <= seg.vmSize, seg.vmSize - at.offset >= 4 else { return .malformedInventory }
                builder.occupy(va, width: 4, .narrowWrite)
            case (_, 1):
                guard at.offset <= seg.vmSize, seg.vmSize - at.offset >= 8 else { return .malformedInventory }
                builder.occupy(va, kind == .bind ? .bind : .weakLazy)
            default:
                return .unsupportedFormat
            }
            return nil
        }

        func advance(_ amount: UInt64) { at.offset = at.offset &+ amount }

        while !r.atEnd {
            guard let op = r.byte() else { return r.failure }
            let imm = UInt64(op & 0x0f)
            let code = op & 0xf0
            switch kind {
            case .rebase:
                switch code {
                case 0x00:
                    return r.restIsZero() ? nil : .malformedInventory
                case 0x10: type = imm
                case 0x20:
                    at.segment = Int(imm); at.segmentSet = true
                    guard let o = r.uleb() else { return r.failure }
                    at.offset = o
                case 0x30:
                    guard let a = r.uleb() else { return r.failure }
                    advance(a)
                case 0x40: advance(imm &* 8)
                case 0x50:
                    for _ in 0..<imm {
                        if let f = write() { return f }
                        advance(8)
                    }
                case 0x60:
                    guard let n = r.uleb() else { return r.failure }
                    guard n <= UInt64(SwiftSlotInventory.maxEvents) else { return .budget }
                    for _ in 0..<n {
                        if let f = write() { return f }
                        advance(8)
                    }
                case 0x70:
                    if let f = write() { return f }
                    advance(8)
                    guard let a = r.uleb() else { return r.failure }
                    advance(a)
                case 0x80:
                    guard let n = r.uleb(), let skip = r.uleb() else { return r.failure }
                    guard n <= UInt64(SwiftSlotInventory.maxEvents) else { return .budget }
                    for _ in 0..<n {
                        if let f = write() { return f }
                        advance(8); advance(skip)
                    }
                default:
                    return .unsupportedOpcode
                }
            case .bind, .weakBind, .lazyBind:
                switch code {
                case 0x00:
                    if kind.doneTerminates { return r.restIsZero() ? nil : .malformedInventory }
                    // Lazy entries end in DONE; the cursor state resets per entry in dyld, so keep going.
                case 0x10, 0x30: break
                case 0x20: guard r.uleb() != nil else { return r.failure }
                case 0x40: guard r.skipCString() else { return r.failure }
                case 0x50: type = imm
                case 0x60: guard r.sleb() != nil else { return r.failure }
                case 0x70:
                    at.segment = Int(imm); at.segmentSet = true
                    guard let o = r.uleb() else { return r.failure }
                    at.offset = o
                case 0x80:
                    guard let a = r.uleb() else { return r.failure }
                    advance(a)
                case 0x90:
                    if let f = write() { return f }
                    advance(8)
                case 0xa0:
                    if let f = write() { return f }
                    advance(8)
                    guard let a = r.uleb() else { return r.failure }
                    advance(a)
                case 0xb0:
                    if let f = write() { return f }
                    advance(8); advance(imm &* 8)
                case 0xc0:
                    guard let n = r.uleb(), let skip = r.uleb() else { return r.failure }
                    guard n <= UInt64(SwiftSlotInventory.maxEvents) else { return .budget }
                    for _ in 0..<n {
                        if let f = write() { return f }
                        advance(8); advance(skip)
                    }
                default:
                    // 0xd0 threaded binds and unknown opcodes: stop rather than guess.
                    return .unsupportedOpcode
                }
            }
        }
        return nil
    }

    /// The raw 64-bit word stored in the slot, or nil when the slot has no file bytes.
    private static func pointer(data: Data, segment: MachOSegment, offset: UInt64) -> UInt64? {
        guard segment.fileSize >= 8, offset <= segment.fileSize - 8 else { return nil }
        let (file, overflow) = segment.fileOffset.addingReportingOverflow(offset)
        guard !overflow, data.count >= 8, file <= UInt64(data.count - 8) else { return nil }
        var value: UInt64 = 0
        for i in 0..<8 { value |= UInt64(data[data.startIndex + Int(file) + i]) << UInt64(8 * i) }
        return value
    }
}
