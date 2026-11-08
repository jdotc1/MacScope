import Foundation

/// FX-SLOT: a loss-preserving inventory of the 8-byte absolute pointer slots that the dynamic loader
/// may rewrite, built once per image by the Mach-O producers and consumed by the Swift witness
/// extractor. Derived state only: never Codable, never persisted.
///
/// A slot's raw bytes are trusted only when the inventory PROVES the slot untouched (the scope that
/// contains it was completely inspected and no event overlaps it) or proves a rebase (the decoded
/// target replaces the raw word). Every other outcome withholds the raw word. The default is
/// `.unknown`, which fails closed.
struct SwiftSlotInventory: Sendable, Equatable {
    /// Diagnostic vocabulary. App-owned, so it may appear in loader findings.
    enum Reason: String, Sendable, Equatable, CaseIterable {
        // Occupied: a loader mutation overwrites the slot.
        case bind, narrowWrite, relocation, weakLazy, indirectPointer, unresolvedRebase, nonPointer
        // Ambiguous or uninspected.
        case duplicate, truncated, unsupportedOpcode, unsupportedFormat, budget, malformedInventory
        case multiStart, missingDeclaration, duplicateDeclaration, coexistence, cacheImage
        case unknownProducer, extentMismatch, outsideCoverage
    }

    /// What a consumer may do with one 8-byte slot.
    enum Word: Sendable, Equatable {
        case untouched
        case rebase(target: UInt64)
        case occupied(Reason)
        case ambiguous
        case uninspected(Reason)
    }

    /// Selected-slice identity the inventory was built for (R-Q1b). No hashing.
    struct Extent: Sendable, Equatable {
        var offset: UInt64
        var size: UInt64
    }

    struct Write: Sendable, Equatable {
        enum Kind: Sendable, Equatable {
            case rebase(UInt64)
            case occupied(Reason)
        }
        var va: UInt64
        var width: UInt8
        var kind: Kind
    }

    /// One withheld scope, disclosed through `LoaderFinding` (R-Q11). `extent` is a VA range, or nil
    /// when the scope is the whole image.
    struct Withheld: Sendable, Equatable {
        enum Scope: String, Sendable, Equatable {
            case classicImage = "classic-image"
            case relocations
            case chainedPage = "chained-page"
            case multiStart = "multi-start"
            case cap
            case cacheWithheld = "cache-withheld"
            case imageDeclaration = "image-declaration"
        }
        var scope: Scope
        var reason: Reason
        var extent: Range<UInt64>?
    }

    private(set) var writes: [Write] = []
    private(set) var coverage: [Range<UInt64>] = []
    private(set) var blockers: Set<Reason> = []
    private(set) var occupiedRanges: [(range: Range<UInt64>, reason: Reason)] = []
    private(set) var withheld: [Withheld] = []
    private(set) var extent: Extent?

    /// No producer attested: every query is `.uninspected(.unknownProducer)`.
    static let unknown: SwiftSlotInventory = {
        var inventory = SwiftSlotInventory()
        inventory.blockers = [.unknownProducer]
        return inventory
    }()

    /// An attested producer that refuses the whole image for `reason`.
    static func refused(_ scope: Withheld.Scope, _ reason: Reason, extent: Extent? = nil) -> SwiftSlotInventory {
        var builder = Builder()
        builder.block(scope, reason)
        return builder.build(extent: extent)
    }

    static func == (lhs: SwiftSlotInventory, rhs: SwiftSlotInventory) -> Bool {
        lhs.writes == rhs.writes && lhs.coverage == rhs.coverage && lhs.blockers == rhs.blockers
            && lhs.withheld == rhs.withheld && lhs.extent == rhs.extent
            && lhs.occupiedRanges.count == rhs.occupiedRanges.count
            && zip(lhs.occupiedRanges, rhs.occupiedRanges).allSatisfy { $0.range == $1.range && $0.reason == $1.reason }
    }

    /// True when every query is answered from an attested producer for exactly this slice.
    func attested(sliceOffset: UInt64, sliceSize: UInt64) -> SwiftSlotInventory {
        guard let extent else { return self }
        if extent == Extent(offset: sliceOffset, size: sliceSize) { return self }
        return .refused(.imageDeclaration, .extentMismatch)
    }

    /// Re-stamps the identity when the loader's frame differs from the parser's thin-slice frame,
    /// but only when the slice size is the same.
    func rebound(sliceOffset: UInt64, sliceSize: UInt64) -> SwiftSlotInventory {
        guard let extent else { return self }
        var copy = self
        guard extent.size == sliceSize else { return .refused(.imageDeclaration, .extentMismatch) }
        copy.extent = Extent(offset: sliceOffset, size: sliceSize)
        return copy
    }

    /// Answers for the full `[va, va + 8)` extent. Overlap is by extent, never by equal start.
    func word(atSlot va: UInt64) -> Word {
        let (end, overflow) = va.addingReportingOverflow(8)
        guard !overflow else { return .uninspected(.malformedInventory) }

        var hits: [Write.Kind] = []
        var exact = false
        var index = lowerBound(of: va >= 7 ? va - 7 : 0)
        while index < writes.count, writes[index].va < end {
            let write = writes[index]
            let (writeEnd, writeOverflow) = write.va.addingReportingOverflow(UInt64(write.width))
            if writeOverflow || writeEnd > va {
                hits.append(write.kind)
                exact = write.va == va && write.width == 8
            }
            index += 1
        }
        for entry in occupiedRanges where entry.range.lowerBound < end && entry.range.upperBound > va {
            hits.append(.occupied(entry.reason))
            exact = false
        }

        if hits.count >= 2 { return .ambiguous }
        if let only = hits.first {
            switch only {
            case .occupied(let reason):
                return .occupied(reason)
            case .rebase(let target):
                guard exact else { return .occupied(.narrowWrite) }
                if let blocker = firstBlocker { return .uninspected(blocker) }
                return isCovered(va, end) ? .rebase(target: target) : .uninspected(.outsideCoverage)
            }
        }
        if let blocker = firstBlocker { return .uninspected(blocker) }
        return isCovered(va, end) ? .untouched : .uninspected(.outsideCoverage)
    }

    private var firstBlocker: Reason? {
        blockers.min { $0.rawValue < $1.rawValue }
    }

    private func lowerBound(of va: UInt64) -> Int {
        var low = 0, high = writes.count
        while low < high {
            let mid = (low + high) / 2
            if writes[mid].va < va { low = mid + 1 } else { high = mid }
        }
        return low
    }

    private func isCovered(_ start: UInt64, _ end: UInt64) -> Bool {
        var low = 0, high = coverage.count
        while low < high {
            let mid = (low + high) / 2
            if coverage[mid].lowerBound <= start { low = mid + 1 } else { high = mid }
        }
        guard low > 0 else { return false }
        return coverage[low - 1].upperBound >= end
    }

    /// Accumulates events and scopes; `build` sorts and merges.
    struct Builder {
        private(set) var writes: [Write] = []
        private var coverage: [Range<UInt64>] = []
        private var blockers: Set<Reason> = []
        private var occupiedRanges: [(range: Range<UInt64>, reason: Reason)] = []
        private var withheld: [Withheld] = []

        var eventCount: Int { writes.count }

        mutating func rebase(_ va: UInt64, target: UInt64) {
            writes.append(Write(va: va, width: 8, kind: .rebase(target)))
        }

        mutating func occupy(_ va: UInt64, width: UInt8 = 8, _ reason: Reason) {
            writes.append(Write(va: va, width: width, kind: .occupied(reason)))
        }

        mutating func occupyRange(_ range: Range<UInt64>, _ reason: Reason) {
            guard !range.isEmpty else { return }
            occupiedRanges.append((range, reason))
        }

        mutating func cover(_ range: Range<UInt64>) {
            guard !range.isEmpty else { return }
            coverage.append(range)
        }

        /// An image-wide refusal: no slot is untouched or a rebase, but events stay visible.
        mutating func block(_ scope: Withheld.Scope, _ reason: Reason, extent: Range<UInt64>? = nil) {
            blockers.insert(reason)
            withheld.append(Withheld(scope: scope, reason: reason, extent: extent))
        }

        /// A scope-local refusal that is already excluded from coverage by the caller.
        mutating func note(_ scope: Withheld.Scope, _ reason: Reason, extent: Range<UInt64>?) {
            withheld.append(Withheld(scope: scope, reason: reason, extent: extent))
        }

        func build(extent: Extent?) -> SwiftSlotInventory {
            var inventory = SwiftSlotInventory()
            inventory.writes = writes.enumerated().sorted {
                $0.element.va != $1.element.va ? $0.element.va < $1.element.va : $0.offset < $1.offset
            }.map(\.element)
            var merged: [Range<UInt64>] = []
            for range in coverage.sorted(by: { $0.lowerBound < $1.lowerBound }) {
                if let last = merged.last, range.lowerBound <= last.upperBound {
                    merged[merged.count - 1] = last.lowerBound..<max(last.upperBound, range.upperBound)
                } else {
                    merged.append(range)
                }
            }
            inventory.coverage = merged
            inventory.blockers = blockers
            inventory.occupiedRanges = occupiedRanges
            inventory.withheld = withheld
            inventory.extent = extent
            return inventory
        }
    }
}
