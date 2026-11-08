import Foundation

/// Shared local/XPC caller postprocessing. Binary parsing remains in the worker.
/// Works on a private value copy: cancellation never publishes partial derived products.
enum RehydrationDerivedProducts {
    static func rebuild(persisted: ImageAnalysis, loader: RehydrationLoaderProducts,
                        imageBytes: Data, overrides: [UInt64: AddressOverride] = [:],
                        cancellation: AnalysisCancellationToken) throws -> ImageAnalysis {
        try cancellation.check(.rehydrate)
        try loader.validate(imageByteCount: imageBytes.count)
        let overlay = try BytePatchOverlay(patches: overrides.compactMapValues { $0.patch },
                                           mappings: loader.mappings)
        try cancellation.check(.rehydrate)
        var result = persisted
        result.sections = loader.sections
        result.codeDataRanges = loader.codeDataRanges
        result.relocations = loader.relocations
        result.identityEffectiveByteRanges = loader.identityEffectiveByteRanges
        result.machOMetadata = loader.machOMetadata
        result.objcClasses = loader.objcClasses
        result.objcCategories = loader.objcCategories
        result.objcProtocols = loader.objcProtocols
        result.swiftTypes = loader.swiftTypes
        result.swiftConformances = loader.swiftConformances
        result.objcSelectors = loader.objcSelectors
        result.stringLiterals = try ReferencedStringRecovery.recover(
            retained: persisted.stringLiterals, coverage: persisted.stringLiteralCoverage,
            references: persisted.xrefs, sections: loader.sections, bytes: imageBytes,
            sliceOffset: loader.sliceOffset, sliceSize: loader.sliceSize, overlay: overlay,
            checkpoint: { try cancellation.check(.rehydrate) })
        result.constantStrings = ImageConstantStringProvider.build(
            stringLiterals: result.stringLiterals,
            cfStrings: ImageConstantStringProvider.cfStrings(in: persisted.constantStrings)
                .merging(loader.constantCFStrings) { _, loaded in loaded })
        // The loader's table wins when it produced one; else the persisted table (already in
        // `result`); else nil.
        if let table = loader.cfStringBackings { result.cfStringBackings = table }
        result.objcClassReferences = loader.objcClassReferences
        try cancellation.check(.rehydrate)
        result.jumpTables = try resolveJumpTables(instructionRows: persisted.instructions,
            imageBytes: imageBytes, loader: loader, functions: persisted.functions,
            patchOverlay: overlay, byteMappings: loader.mappings, cancellation: cancellation)
        try cancellation.check(.rehydrate)
        result.diagnostics = AnalysisDiagnosticsCollector().collect(.init(
            instructions: result.instructions, controlFlowEdges: result.controlFlowEdges,
            xrefs: result.xrefs, sections: result.sections,
            loaderTruncations: loader.loaderTruncations,
            parserDisagreements: loader.parserDisagreements,
            parserCrossCheckSkip: loader.parserCrossCheckSkip, loaderFindings: loader.loaderFindings))
        try cancellation.check(.rehydrate)
        result.refreshTypeCatalog()
        try cancellation.check(.rehydrate)
        return result
    }

    static func mappedBytes(in bytes: Data, sliceOffset: UInt64, at address: UInt64,
                            count: Int, mappings: [FileAddressMapping]) -> Data? {
        guard let range = FileAddressMapping.resolvedFileRange(
            forVirtualAddress: address, count: count, in: mappings),
            let sliceStart = Int(exactly: sliceOffset), sliceStart <= bytes.count,
            range.upperBound <= bytes.count - sliceStart else { return nil }
        let start = bytes.startIndex + sliceStart + range.lowerBound
        return bytes.subdata(in: start..<(start + count))
    }

    static func resolveJumpTables(
        instructionRows: [InstructionRow],
        imageBytes: Data,
        loader: RehydrationLoaderProducts,
        functions: [FunctionSummary],
        patchOverlay: BytePatchOverlay,
        byteMappings: [FileAddressMapping],
        cancellation: AnalysisCancellationToken,
        work: StartupWorkCounters? = nil
    ) throws -> [UInt64: [UInt64]] {

        // Automatic tables use exactly the same whole-range mapping authority
        // as manual hints. A section cannot read a neighbor's bytes or an alias.
        let readBytes: JumpTableResolver.ByteReader = { virtualAddress, count in
            guard let raw = Self.mappedBytes(in: imageBytes, sliceOffset: loader.sliceOffset, at: virtualAddress,
                                             count: count, mappings: byteMappings) else { return nil }
            guard !cancellation.isCancelled else { return nil }
            return patchOverlay.applying(to: raw, at: virtualAddress)
        }

        // Checked span: a malformed section whose address + size overflows cannot
        // bound jump-table resolution — omit resolution entirely rather than trap
        // or hand the resolver a wrapped range. (A zero-size section previously
        // produced an empty range that resolved nothing; returning [:] is the same.)
        var result: [UInt64: [UInt64]] = [:]
        let sections = executableCodeSections(sections: loader.sections, layout: loader.preferredSegmentLayout, mappings: byteMappings)
        let sortedFunctions = functions.sorted { $0.startAddress < $1.startAddress }
        var previousEnd: UInt64 = 0
        var considered = 0, accepted = 0, copiedRows = 0
        defer {
            if let work {
                work.add(.jumpFunctionsConsidered, considered)
                work.add(.jumpFunctionsAccepted, accepted)
                work.add(.jumpRowSliceCopies, accepted)
                work.add(.jumpRowsCopied, copiedRows)
            }
        }
        for (index, function) in sortedFunctions.enumerated() {
            considered += 1
            try cancellation.check()
            let overlapBefore = previousEnd > function.startAddress
            previousEnd = max(previousEnd, function.endAddress)
            guard function.startAddress < function.endAddress, !overlapBefore,
                  index + 1 == sortedFunctions.count || sortedFunctions[index + 1].startAddress >= function.endAddress,
                  let section = sections.first(where: {
                      function.startAddress >= $0.address && function.endAddress <= $0.address + $0.size
                  }) else { continue }
            let rows = Array(instructionRows[Self.addressIndex(function.startAddress, in: instructionRows, address: \.address)
                ..< Self.addressIndex(function.endAddress, in: instructionRows, address: \.address)])
            accepted += 1
            copiedRows += rows.count
            let recovered = JumpTableResolver().resolve(instructions: rows, readBytes: readBytes,
                codeRange: .init(lowerBound: function.startAddress, upperBound: min(function.endAddress, section.address + section.size)))
            let decodedTargets = Set(rows.filter { !$0.bytes.isEmpty }.map(\.address))
            for (site, targets) in recovered where targets.allSatisfy({ decodedTargets.contains($0) }) {
                result[site] = targets
            }
        }
        try cancellation.check()
        return result
    }

    static func executableCodeSections(sections: [SectionSummary], layout: MachOPreferredSegmentLayout?,
                                       mappings: [FileAddressMapping]) -> [SectionSummary] {
        let candidates = sections.filter { $0.isExecutable && !$0.isZeroFill }
        guard candidates.count <= 256 else { return [] }
        return candidates.compactMap { section in
            let size = min(section.size, section.fileSize ?? section.size)
            guard size > 0, let count = Int(exactly: size),
                  let span = checkedSpan(start: section.address, size: size),
                  let file = FileAddressMapping.resolvedFileRange(forVirtualAddress: section.address, count: count, in: mappings),
                  UInt64(file.lowerBound) == section.fileOffset else { return nil }
            guard sections.filter({ other in
                guard let otherSpan = checkedSpan(start: other.address, size: other.size) else { return false }
                return otherSpan.overlaps(span)
            }).count == 1 else { return nil }
            if let layout = layout {
                let owners = layout.records.filter { record in
                    guard let end = checkedSpan(start: record.preferredVMStart,
                                                          size: min(record.preferredVMSize, record.fileSize)) else { return false }
                    return span.lowerBound >= end.lowerBound && span.upperBound <= end.upperBound
                        && record.sliceRelativeFileOffset <= section.fileOffset
                        && section.fileOffset - record.sliceRelativeFileOffset == section.address - record.preferredVMStart
                }
                guard owners.count == 1, let owner = owners.first,
                      owner.initialProtections & 4 != 0 else { return nil }
            }
            var bounded = section
            bounded.size = size
            bounded.fileSize = size
            return bounded
        }.sorted { $0.address < $1.address }
    }

    // Same nonempty, nonwrapping half-open span required at the original engine seam.
    private static func checkedSpan(start: UInt64, size: UInt64) -> Range<UInt64>? {
        let end = start.addingReportingOverflow(size)
        guard size > 0, !end.overflow else { return nil }
        return start..<end.partialValue
    }

    private static func addressIndex<Element>(_ value: UInt64, in rows: [Element],
                                               address: KeyPath<Element, UInt64>) -> Int {
        var lower = 0
        var upper = rows.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            if rows[middle][keyPath: address] < value { lower = middle + 1 } else { upper = middle }
        }
        return lower
    }

}

/// Recovers bounded, already-referenced fields from loader-authorized string sections.
/// The original coverage is retained: point lookups do not prove complete extraction.
enum ReferencedStringRecovery {
    private struct Span {
        let ordinal: Int
        let section: SectionSummary
        let end: UInt64
        let physicalStart: Int
        let count: Int
    }
    private struct Position: Comparable {
        let section: Int
        let address: UInt64
        static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.section == rhs.section ? lhs.address < rhs.address : lhs.section < rhs.section
        }
    }
    static let maxRows = 270_336, maxCandidates = 8_192, maxReferences = 100_000
    static let maxSections = 65_536, maxBytes = 8 << 20, maxText = 64 << 20, maxField = 4_096

    /// Work tally for one invocation. Each loop is 0 = not entered, 1 = entered and not
    /// yet finished (an early return or throw leaves it there), 2 = ran to its end.
    private struct Tally {
        var sectionEntries = 0, sectionState = 0
        var validated = 0, validatedState = 0
        var references = 0, referencesState = 0
        var candidates = 0, additions = 0, candidatesState = 0
        var merged = 0, mergeState = 0

        func flush(into work: StartupWorkCounters, returned: Bool) {
            func loop(_ field: StartupWorkCounters.Field, _ count: Int, _ state: Int) {
                guard state != 0 else { return }
                work.add(field, count)
                if state == 1 || !returned { work.interrupt(field) }
            }
            work.enter(.string)
            if returned { work.add(.stringRecoveryCalls) } else { work.begin(.stringRecoveryCalls); work.interrupt(.stringRecoveryCalls) }
            loop(.stringSectionEntriesVisited, sectionEntries, sectionState)
            loop(.stringRetainedEntriesValidated, validated, validatedState)
            loop(.stringReferencesVisited, references, referencesState)
            loop(.stringCandidatesVisited, candidates, candidatesState)
            if candidatesState != 0 {
                work.add(.stringAdditions, additions)
                if candidatesState == 1 || !returned { work.interrupt(.stringAdditions) }
            }
            loop(.stringRetainedMergeVisits, merged, mergeState)
        }
    }

    static func recover(retained: [StringLiteralSummary], coverage: StringLiteralCoverage?,
                        references: [XRef], sections: [SectionSummary], bytes: Data,
                        sliceOffset: UInt64, sliceSize: UInt64?, overlay: BytePatchOverlay,
                        work: StartupWorkCounters? = nil,
                        checkpoint: () throws -> Void) throws -> [StringLiteralSummary] {
        var tally = Tally()
        do {
            let result = try recover(retained: retained, coverage: coverage, references: references,
                sections: sections, bytes: bytes, sliceOffset: sliceOffset, sliceSize: sliceSize,
                overlay: overlay, tally: &tally, checkpoint: checkpoint)
            if let work { tally.flush(into: work, returned: true) }
            return result
        } catch {
            if let work { tally.flush(into: work, returned: false) }
            throw error
        }
    }

    private static func recover(retained: [StringLiteralSummary], coverage: StringLiteralCoverage?,
                        references: [XRef], sections: [SectionSummary], bytes: Data,
                        sliceOffset: UInt64, sliceSize: UInt64?, overlay: BytePatchOverlay,
                        tally: inout Tally,
                        checkpoint: () throws -> Void) throws -> [StringLiteralSummary] {
        try checkpoint()
        guard coverage != .complete, coverage != .notAttempted, !references.isEmpty,
              retained.count < maxRows, sections.count <= maxSections,
              let start = Int(exactly: sliceOffset), start <= bytes.count else { return retained }
        let extent = sliceSize ?? UInt64(bytes.count - start)
        guard extent <= UInt64(bytes.count - start) else { return retained }
        var spans: [Span] = [], ranges: [(UInt64, UInt64)] = []
        tally.sectionState = 1
        for (ordinal, section) in sections.enumerated() where section.size > 0 {
            tally.sectionEntries += 1
            if ordinal.isMultiple(of: 128) { try checkpoint() }
            let end = section.address.addingReportingOverflow(section.size)
            guard !end.overflow else { return retained }
            ranges.append((section.address, end.partialValue))
            guard section.containsCStringLiterals == true else { continue }
            guard !section.isZeroFill, section.fileOffset <= extent,
                  section.size <= extent - section.fileOffset,
                  section.fileSize.map({ $0 >= section.size }) ?? true,
                  let offset = Int(exactly: section.fileOffset), let count = Int(exactly: section.size) else { return retained }
            let objcName = ["__objc_methname", "__objc_classname", "__objc_methtype"]
                .contains { section.name == $0 || section.name.hasSuffix("," + $0) }
            // Parser extraction visits ordinary sections first, followed by Objective-C
            // name sections, retaining input section order within each group.
            let extractionOrdinal = ordinal + (objcName ? sections.count : 0)
            spans.append(Span(ordinal: extractionOrdinal, section: section, end: end.partialValue,
                              physicalStart: start + offset, count: count))
        }
        tally.sectionState = 2
        guard !spans.isEmpty else { return retained }
        ranges.sort { $0.0 < $1.0 }
        for index in ranges.indices.dropFirst() {
            if index.isMultiple(of: 128) { try checkpoint() }
            guard ranges[index - 1].1 <= ranges[index].0 else { return retained }
        }
        spans.sort { $0.section.address < $1.section.address }
        func owner(_ address: UInt64) -> Span? {
            var low = 0, high = spans.count
            while low < high {
                let middle = low + (high - low) / 2
                if spans[middle].section.address <= address { low = middle + 1 } else { high = middle }
            }
            guard low > 0, address < spans[low - 1].end else { return nil }
            return spans[low - 1]
        }
        var positions: [Position] = [], existing = Set<UInt64>(), textCount = 0
        tally.validatedState = 1
        for (index, row) in retained.enumerated() {
            tally.validated += 1
            if index.isMultiple(of: 128) { try checkpoint() }
            let count = row.value.utf8.prefix(maxText - textCount + 1).count
            guard count <= maxText - textCount, let span = owner(row.address),
                  span.section.name == row.sourceSection else { return retained }
            textCount += count
            let position = Position(section: span.ordinal, address: row.address)
            if let last = positions.last, position < last { return retained }
            positions.append(position); existing.insert(row.address)
        }
        tally.validatedState = 2
        var candidates: [UInt64] = [], seen = Set<UInt64>()
        tally.referencesState = 1
        for (index, ref) in references.prefix(maxReferences).enumerated() {
            tally.references += 1
            if index.isMultiple(of: 128) { try checkpoint() }
            guard ref.kind == XRefKind.data || ref.kind == XRefKind.string,
                  owner(ref.to) != nil, seen.insert(ref.to).inserted else { continue }
            candidates.append(ref.to)
            if candidates.count == maxCandidates { break }
        }
        tally.referencesState = 2
        var readCount = 0, additions: [(Position, StringLiteralSummary)] = []
        tally.candidatesState = 1
        for address in candidates {
            tally.candidates += 1
            try checkpoint()
            guard retained.count + additions.count < maxRows, let span = owner(address) else { break }
            let relative = Int(address - span.section.address), physical = span.physicalStart + relative
            let prefix = relative > 0 ? 1 : 0
            let available = min(maxField + 1, span.count - relative)
            // Refuse this candidate if any effective-byte override could change the field or
            // its boundary. Existing rows and raw xrefs are never silently rewritten.
            let checkAddress = prefix == 1 ? address - 1 : address
            if overlay.intersects(address: checkAddress, count: available + prefix) { continue }
            if prefix == 1 {
                guard readCount < maxBytes else { break }
                readCount += 1
                guard bytes[bytes.startIndex + physical - 1] == 0 else { continue }
            }
            var field = Data(), terminated = false
            for offset in 0..<available {
                guard readCount < maxBytes else { break }
                readCount += 1
                let byte = bytes[bytes.startIndex + physical + offset]
                if byte == 0 { terminated = true; break }
                field.append(byte)
            }
            guard terminated, !field.isEmpty, field.count <= maxField,
                  field.allSatisfy({ $0 == 9 || $0 == 10 || $0 == 13 || $0 >= 0x20 }),
                  let value = String(data: field, encoding: .utf8),
                  !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !existing.contains(address) else { continue }
            guard field.count <= maxText - textCount else { break }
            textCount += field.count
            additions.append((Position(section: span.ordinal, address: address),
                StringLiteralSummary(id: UUID(), value: value, address: address,
                                     sourceSection: span.section.name, byteLength: field.count)))
            tally.additions += 1
        }
        tally.candidatesState = 2
        guard !additions.isEmpty else { try checkpoint(); return retained }
        additions.sort { $0.0 < $1.0 }
        var result: [StringLiteralSummary] = []; result.reserveCapacity(retained.count + additions.count)
        var next = 0
        tally.mergeState = 1
        for (index, row) in retained.enumerated() {
            tally.merged += 1
            if index.isMultiple(of: 128) { try checkpoint() }
            while next < additions.count, additions[next].0 < positions[index] {
                result.append(additions[next].1); next += 1
            }
            result.append(row)
        }
        result.append(contentsOf: additions[next...].map { $0.1 })
        tally.mergeState = 2
        try checkpoint()
        return result
    }
}
