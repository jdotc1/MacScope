import Foundation

/// Scalar-only immutable products of one section's immutable input.
struct DiscoveryPreparation {
    let decodedAddresses: Set<UInt64>
    let baselineDirectCalls: Set<UInt64>
}

/// Owned by one synchronous analyze invocation, never by the engine.
/// A section ordinal is valid only for that invocation's fixed section array.
final class DiscoveryPreparationStore {
    struct Statistics {
        var decodedAddressBuilds = 0
        var unavailableAddressBuilds = 0
        var directCallBuilds = 0
        var admissions = 0
        var refusals = 0
        var retainedEntries = 0
    }
    static let defaultEntryLimit = 8_388_608
    private let entryLimit: Int
    private var reservedEntries = 0
    private var sections: [Int: DiscoveryPreparation] = [:]
    private var unavailableBySection: [Int: Set<UInt64>] = [:]
    private var refused: Set<Int> = []
    private(set) var statistics = Statistics()
    /// Optional Stage A observer mirroring the mutation events below; nil adds no work.
    private let work: StartupWorkCounters?

    init(entryLimit: Int = DiscoveryPreparationStore.defaultEntryLimit,
         work: StartupWorkCounters? = nil) {
        self.entryLimit = max(0, entryLimit)
        self.work = work
    }

    /// Scalar-only admission seam; no allocation and no mutation.
    func canAdmit(entryUpperBound: Int) -> Bool {
        entryUpperBound >= 0 && entryUpperBound <= entryLimit - reservedEntries
    }

    func prepare(sectionOrdinal: Int, instructions: [DecodedInstruction],
                 codeStart: UInt64?, codeEnd: UInt64?,
                 existingStarts: Set<UInt64>) -> DiscoveryPreparation? {
        prepare(sectionOrdinal: sectionOrdinal, rows: instructions[...],
            codeStart: codeStart, codeEnd: codeEnd, existingStarts: existingStarts)
    }

    func prepare(sectionOrdinal: Int, rows instructions: ArraySlice<DecodedInstruction>,
                 codeStart: UInt64?, codeEnd: UInt64?,
                 existingStarts: Set<UInt64>) -> DiscoveryPreparation? {
        if let value = sections[sectionOrdinal] { return value }
        if refused.contains(sectionOrdinal) { return nil }
        // Each of the three sets contains at most N entries. Check overflow
        // before multiplication; reservation precedes all set construction.
        guard instructions.count <= Int.max / 3,
              canAdmit(entryUpperBound: instructions.count * 3) else {
            refused.insert(sectionOrdinal)
            statistics.refusals += 1
            work?.add(.cacheRefusals)
            work?.publishStoreGauge(current: statistics.retainedEntries)
            return nil
        }
        reservedEntries += instructions.count * 3
        let addresses = Set(instructions.map(\.address))
        statistics.decodedAddressBuilds += 1
        work?.add(.decodedAddressBuilds)
        let calls = Self.directCalls(rows: instructions, addresses: addresses,
            codeStart: codeStart, codeEnd: codeEnd, existingStarts: existingStarts)
        statistics.directCallBuilds += 1
        work?.add(.directCallBuilds)
        let value = DiscoveryPreparation(decodedAddresses: addresses, baselineDirectCalls: calls)
        sections[sectionOrdinal] = value
        statistics.admissions += 1
        statistics.retainedEntries += addresses.count + calls.count
        if let work {
            work.add(.cacheAdmissions)
            work.publishStoreGauge(current: statistics.retainedEntries)
        }
        return value
    }

    /// Called at the original unavailable-set first use, not at admission.
    func unavailable(sectionOrdinal: Int, instructions: [DecodedInstruction]) -> Set<UInt64>? {
        unavailable(sectionOrdinal: sectionOrdinal, rows: instructions[...])
    }

    func unavailable(sectionOrdinal: Int, rows instructions: ArraySlice<DecodedInstruction>) -> Set<UInt64>? {
        guard sections[sectionOrdinal] != nil else { return nil }
        if let value = unavailableBySection[sectionOrdinal] { return value }
        let value = Set(instructions.lazy.filter { $0.mnemonic == "unavailable" }.map(\.address))
        unavailableBySection[sectionOrdinal] = value
        statistics.unavailableAddressBuilds += 1
        statistics.retainedEntries += value.count
        if let work {
            work.add(.unavailableAddressBuilds)
            work.publishStoreGauge(current: statistics.retainedEntries)
        }
        return value
    }

    /// Drop all retained address entries before the listing phase begins.
    func release() {
        sections.removeAll(keepingCapacity: false)
        unavailableBySection.removeAll(keepingCapacity: false)
        refused.removeAll(keepingCapacity: false)
        reservedEntries = 0
        statistics.retainedEntries = 0
        work?.publishStoreGauge(current: 0)
    }

    static func directCalls(instructions: [DecodedInstruction], addresses: Set<UInt64>,
                            codeStart: UInt64?, codeEnd: UInt64?,
                            existingStarts: Set<UInt64>) -> Set<UInt64> {
        directCalls(rows: instructions[...], addresses: addresses,
            codeStart: codeStart, codeEnd: codeEnd, existingStarts: existingStarts)
    }

    static func directCalls(rows instructions: ArraySlice<DecodedInstruction>, addresses: Set<UInt64>,
                            codeStart: UInt64?, codeEnd: UInt64?,
                            existingStarts: Set<UInt64>) -> Set<UInt64> {
        Set(instructions.compactMap { instruction -> UInt64? in
            guard instruction.flow == .call, let target = instruction.branchTarget else { return nil }
            guard target != instruction.address else { return nil }
            guard !existingStarts.contains(target) else { return nil }
            guard addresses.contains(target) else { return nil }
            if let codeStart, let codeEnd {
                guard target >= codeStart && target < codeEnd else { return nil }
            }
            return target
        })
    }
}
