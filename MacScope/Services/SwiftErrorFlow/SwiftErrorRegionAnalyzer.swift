// Bounded subset of AIRS f52d333's _error_region, _caller_direct_edges,
// _flag_entries and _region_incoming. No file I/O, imported reports or execution.
public enum SwiftErrorRegionAnalyzer {
    public static let maximumRegionWords = 16
    public static let maximumCallerWords = 4_096
    public static let maximumRegions = 256
    public static let maximumEntryDetails = 16

    public static func analyze(_ input: SwiftErrorFlowRequest) -> SwiftErrorRegionReport {
        let edges = SwiftErrorFlowAnalyzer.analyze(input, model: .registerCopiesV2)
        guard edges.status == .analyzed else {
            return .init(edgeReport: edges, recoveredEdgeCount: 0, omittedRegionCount: 0,
                         regionDetailsComplete: true, callerScanCount: 0, scannedWordCount: 0, regions: [])
        }
        // The edge producer already validated unique, nonoverlapping function ranges.
        let functions = Dictionary(uniqueKeysWithValues: input.functions.map { ($0.start, $0) })
        var scans: [UInt64: CallerScan] = [:]
        var regions: [SwiftErrorRegionResult] = []
        for edge in edges.edges.prefix(maximumRegions) {
            guard let function = functions[edge.callerStart] else { continue }
            let scan: CallerScan
            if let existing = scans[function.start] {
                scan = existing
            } else {
                scan = scanCaller(input.code, function)
                scans[function.start] = scan
            }
            let window = validate(scan, start: edge.callAddress + 4, end: edge.testAddress + 4,
                                  scope: .postcallWindow)
            regions.append(region(input.code, edge, function, scan, window))
        }
        let omitted = edges.edges.count - regions.count
        return .init(edgeReport: edges, recoveredEdgeCount: edges.edges.count, omittedRegionCount: omitted,
                     regionDetailsComplete: omitted == 0, callerScanCount: scans.count,
                     scannedWordCount: scans.values.reduce(0) { $0 + $1.scannedWordCount }, regions: regions)
    }

    private struct CallerScan {
        let callerStart: UInt64
        let callerWordCount: Int
        let scannedWordCount: Int
        let directEdges: [SwiftErrorRegionWord]
        let unclassifiedWordCount: Int
        let unclassifiedWords: [SwiftErrorRegionWord]

        var complete: Bool { scannedWordCount == callerWordCount }
        var endExclusive: UInt64 { callerStart + UInt64(scannedWordCount) * 4 }
    }

    private static func scanCaller(_ code: SwiftErrorFlowCode, _ function: SwiftErrorFlowFunction) -> CallerScan {
        let first = Int((function.start - code.baseAddress) / 4)
        let count = Int((function.endExclusive - function.start) / 4)
        let retained = min(count, maximumCallerWords)
        var direct: [SwiftErrorRegionWord] = []
        var unknown: [SwiftErrorRegionWord] = []
        var unknownCount = 0
        for index in 0..<retained {
            let address = function.start + UInt64(index) * 4
            let word = code.words[first + index]
            if let row = classify(word, at: address) {
                if row.targetAddress != nil { direct.append(row) }
            } else {
                unknownCount += 1
                if unknown.count < maximumEntryDetails {
                    unknown.append(.init(address: address, word: word, kind: "unclassified",
                                         targetAddress: nil, opaqueCall: false))
                }
            }
        }
        return .init(callerStart: function.start, callerWordCount: count, scannedWordCount: retained,
                     directEdges: direct, unclassifiedWordCount: unknownCount, unclassifiedWords: unknown)
    }

    private static func validate(_ scan: CallerScan, start: UInt64, end: UInt64,
                                 scope: SwiftErrorEntryScope) -> SwiftErrorEntryValidation {
        var count = 0
        var details: [SwiftErrorRegionWord] = []
        for row in scan.directEdges {
            guard let target = row.targetAddress, target >= start, target < end else { continue }
            // Region-internal calls are not side entries. The alias/flag window
            // has no such exception: every explicit entry may bypass earlier words.
            if scope == .region, row.address >= start, row.address < end { continue }
            count += 1
            if details.count < maximumEntryDetails { details.append(row) }
        }
        let status: SwiftErrorEntryStatus = count > 0 ? .unexpected
            : (!scan.complete || scan.unclassifiedWordCount > 0 ? .unresolved : .noUnexpected)
        return .init(scope: scope, status: status, protectedStartAddress: start, protectedEndExclusive: end,
                     callerStart: scan.callerStart, callerWordCount: scan.callerWordCount,
                     scannedWordCount: scan.scannedWordCount, callerScanComplete: scan.complete,
                     unexpectedEntryCount: count, unexpectedEntries: details,
                     entryDetailsComplete: details.count == count,
                     unclassifiedWordCount: scan.unclassifiedWordCount,
                     unclassifiedWords: scan.unclassifiedWords,
                     unclassifiedDetailsComplete: scan.unclassifiedWords.count == scan.unclassifiedWordCount)
    }

    private static func region(_ code: SwiftErrorFlowCode, _ edge: SwiftErrorFlowEdge,
                               _ function: SwiftErrorFlowFunction, _ scan: CallerScan,
                               _ window: SwiftErrorEntryValidation) -> SwiftErrorRegionResult {
        var words: [SwiftErrorRegionWord] = []
        var calls = 0
        func decline(_ reason: SwiftErrorRegionDecline) -> SwiftErrorRegionResult {
            .init(edge: edge, status: .declined, reason: reason, startAddress: nil, endExclusive: nil,
                  joinAddress: nil, instructions: words, opaqueCallCount: calls,
                  postcallWindow: window, incomingEntries: nil)
        }
        let start = edge.errorAddress, join = edge.successAddress
        guard start == edge.testAddress + 4, start < join,
              start >= function.start, join < function.endExclusive else { return decline(.unsupportedLayout) }
        guard (join - start) / 4 <= UInt64(maximumRegionWords) else { return decline(.wordBudgetExceeded) }
        guard join <= scan.endExclusive else { return decline(.outsideCallerScan) }
        // Match the donor's stricter CMP admission; its flag window must be clear.
        // CB-based raw intervals survive conflicts, with both checks exposed separately.
        if edge.comparisonAddress != nil, window.status != .noUnexpected {
            return decline(.postcallEntriesNotClear)
        }
        var address = start
        while address < join {
            let word = code.words[Int((address - code.baseAddress) / 4)]
            guard let row = classify(word, at: address) else {
                words.append(.init(address: address, word: word, kind: "unclassified",
                                   targetAddress: nil, opaqueCall: false))
                return decline(word & 0xfc000000 == 0x94000000 ? .invalidCallTarget : .unmodeledInstruction)
            }
            words.append(row)
            switch row.kind {
            case "nop", "mov", "movz", "movn": break
            case "bl": calls += 1
            case "b":
                guard address + 4 == join, row.targetAddress == join else { return decline(.unmodeledControlFlow) }
            default: return decline(.unmodeledInstruction)
            }
            address += 4
        }
        return .init(edge: edge, status: .candidate, reason: nil, startAddress: start, endExclusive: join,
                     joinAddress: join, instructions: words, opaqueCallCount: calls, postcallWindow: window,
                     incomingEntries: validate(scan, start: start, end: join, scope: .region))
    }

    /// A small exact classifier, intentionally narrower than the donor's general
    /// decoder. Other words remain unknown; a missing direct edge never proves absence.
    private static func classify(_ word: UInt32, at address: UInt64) -> SwiftErrorRegionWord? {
        func ordinary(_ kind: String) -> SwiftErrorRegionWord {
            .init(address: address, word: word, kind: kind, targetAddress: nil, opaqueCall: false)
        }
        func direct(_ kind: String, _ immediate: UInt32, bits: Int) -> SwiftErrorRegionWord? {
            let raw = Int64(immediate)
            let signed = raw & (Int64(1) << (bits - 1)) == 0 ? raw : raw - (Int64(1) << bits)
            let delta = signed * 4
            let target: UInt64
            if delta >= 0 {
                let sum = address.addingReportingOverflow(UInt64(delta))
                guard !sum.overflow else { return nil }
                target = sum.partialValue
            } else {
                let magnitude = UInt64(-delta)
                guard address >= magnitude else { return nil }
                target = address - magnitude
            }
            return .init(address: address, word: word, kind: kind, targetAddress: target, opaqueCall: kind == "bl")
        }
        if word & 0xfc000000 == 0x14000000 { return direct("b", word & 0x03ffffff, bits: 26) }
        if word & 0xfc000000 == 0x94000000 { return direct("bl", word & 0x03ffffff, bits: 26) }
        if word & 0xff000010 == 0x54000000, word & 15 < 14 {
            return direct("bcond", (word >> 5) & 0x7ffff, bits: 19)
        }
        if word & 0x7e000000 == 0x34000000 {
            let width = word & 0x80000000 == 0 ? "w" : "x"
            return direct(width + (word & 0x01000000 == 0 ? "cbz" : "cbnz"), (word >> 5) & 0x7ffff, bits: 19)
        }
        if word & 0x7e000000 == 0x36000000 {
            return direct(word & 0x01000000 == 0 ? "tbz" : "tbnz", (word >> 5) & 0x3fff, bits: 14)
        }
        if word == 0xd503201f { return ordinary("nop") }
        // Canonical RET is a classified terminal only, never proof of indirect-entry exclusion.
        if word == 0xd65f03c0 { return ordinary("ret") }
        if word & 0xffe0ffe0 == 0xaa0003e0 { return ordinary("mov") }
        if word & 0xff800000 == 0xd2800000 { return ordinary("movz") }
        if word & 0xff800000 == 0x92800000 { return ordinary("movn") }
        if word & 0xfffffc1f == 0xf100001f { return ordinary("cmp_zero") }
        return nil
    }
}
