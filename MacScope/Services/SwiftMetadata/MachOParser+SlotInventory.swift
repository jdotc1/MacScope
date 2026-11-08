import Foundation

extension MachOParser {
    /// FX-SLOT assembler: builds the one per-image loader-slot inventory from the parser's own decoded
    /// state. Anything it cannot prove fails closed and is recorded as a withheld scope (R-Q11).
    /// Extent is the parser's own thin-slice frame (offset 0); the loader re-stamps it (`rebound`).
    func buildSlotInventory(data: Data, header: MachOHeader, loadCommands: [MachOLoadCommand],
                            segments: [MachOSegment], sections: [MachOSection],
                            dyldChainedFixups: MachODyldChainedFixups?,
                            isCacheImage: Bool) -> SwiftSlotInventory {
        let extent = SwiftSlotInventory.Extent(offset: 0, size: UInt64(data.count))
        // R-Q2a: dyld shared cache images are withheld until the cache producer lands.
        if isCacheImage || header.flags & 0x8000_0000 != 0 {
            return .refused(.cacheWithheld, .cacheImage, extent: extent)
        }
        var builder = SwiftSlotInventory.Builder()

        // Declared relocations (R-Q4b): any nonzero count, or an unreadable count, blocks the image.
        var relocationsBlocked: SwiftSlotInventory.Reason?
        if sections.contains(where: { $0.relocationCount != 0 }) { relocationsBlocked = .relocation }
        for command in loadCommands where command.command == MachOConstants.loadCommandDysymtab {
            if let ext = Self.slotWord(data, command.offset, 68, command.commandSize, minSize: 80),
               let local = Self.slotWord(data, command.offset, 76, command.commandSize, minSize: 80) {
                if ext != 0 || local != 0 { relocationsBlocked = relocationsBlocked ?? .relocation }
            } else {
                relocationsBlocked = relocationsBlocked ?? .malformedInventory
            }
        }
        if let reason = relocationsBlocked { builder.block(.relocations, reason) }

        // Indirect-pointer sections are loader-owned storage (never witness tables).
        let indirectTypes: Set<UInt32> = [0x6, 0x7, 0x10, 0x14]
        for section in sections where indirectTypes.contains(section.flags & MachOConstants.sectionTypeMask) {
            let (end, overflow) = section.address.addingReportingOverflow(section.size)
            if !overflow { builder.occupyRange(section.address..<end, .indirectPointer) }
        }

        // Declarations.
        let infoCommands = loadCommands.filter {
            $0.command == MachOConstants.loadCommandDyldInfo || $0.command == MachOConstants.loadCommandDyldInfoOnly
        }
        let chainedCommands = loadCommands.filter { $0.command == MachOConstants.loadCommandDyldChainedFixups }
        if infoCommands.count > 1 || chainedCommands.count > 1 {
            builder.block(.imageDeclaration, .duplicateDeclaration)
            return builder.build(extent: extent)
        }
        if !chainedCommands.isEmpty {
            if let info = infoCommands.first {
                // Chained and classic coexist only harmlessly when every classic stream is empty.
                let sizes = [12, 20, 28, 36].map { Self.slotWord(data, info.offset, $0, info.commandSize, minSize: 48) }
                if sizes.contains(where: { $0 == nil || $0 != 0 }) {
                    builder.block(.imageDeclaration, .coexistence)
                    return builder.build(extent: extent)
                }
            }
            return buildChainedSlotInventory(&builder, data: data, extent: extent, segments: segments,
                                             dyldChainedFixups: dyldChainedFixups)
        }
        guard let info = infoCommands.first else {
            builder.block(.imageDeclaration, .missingDeclaration)
            return builder.build(extent: extent)
        }
        guard info.commandSize >= 48,
              let rebaseOff = Self.slotWord(data, info.offset, 8, info.commandSize, minSize: 48),
              let rebaseSize = Self.slotWord(data, info.offset, 12, info.commandSize, minSize: 48),
              let bindOff = Self.slotWord(data, info.offset, 16, info.commandSize, minSize: 48),
              let bindSize = Self.slotWord(data, info.offset, 20, info.commandSize, minSize: 48),
              let weakOff = Self.slotWord(data, info.offset, 24, info.commandSize, minSize: 48),
              let weakSize = Self.slotWord(data, info.offset, 28, info.commandSize, minSize: 48),
              let lazyOff = Self.slotWord(data, info.offset, 32, info.commandSize, minSize: 48),
              let lazySize = Self.slotWord(data, info.offset, 36, info.commandSize, minSize: 48) else {
            builder.block(.classicImage, .malformedInventory)
            return builder.build(extent: extent)
        }
        func stream(_ offset: UInt32, _ size: UInt32) -> Range<Int> {
            Int(offset)..<(Int(offset) + Int(size))
        }
        let failure = ClassicSlotInventoryProducer.decode(
            data: data,
            streams: .init(rebase: stream(rebaseOff, rebaseSize), bind: stream(bindOff, bindSize),
                           weakBind: stream(weakOff, weakSize), lazyBind: stream(lazyOff, lazySize)),
            segments: segments, into: &builder)
        if let failure {
            builder.block(.classicImage, failure)
        } else {
            Self.coverSegments(segments, &builder)
        }
        return builder.build(extent: extent)
    }

    static func coverSegments(_ segments: [MachOSegment], _ builder: inout SwiftSlotInventory.Builder) {
        for segment in segments {
            let (end, overflow) = segment.vmAddress.addingReportingOverflow(max(segment.vmSize, segment.fileSize))
            if !overflow { builder.cover(segment.vmAddress..<end) }
        }
    }

    /// A little-endian u32 inside a load command, or nil when it lies outside the command or the data.
    fileprivate static func slotWord(_ data: Data, _ commandOffset: UInt64, _ field: Int,
                                     _ commandSize: UInt32, minSize: Int) -> UInt32? {
        guard Int(commandSize) >= minSize, field + 4 <= Int(commandSize) else { return nil }
        let (start, overflow) = commandOffset.addingReportingOverflow(UInt64(field))
        guard !overflow, start <= UInt64(Int.max - 4), Int(start) + 4 <= data.count else { return nil }
        var value: UInt32 = 0
        for i in 0..<4 { value |= UInt32(data[data.startIndex + Int(start) + i]) << UInt32(8 * i) }
        return value
    }
}
