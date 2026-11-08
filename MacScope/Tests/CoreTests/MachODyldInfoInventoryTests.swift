import Foundation
import XCTest
@testable import MacScope

/// FX-SLOT slice B: the classic `LC_DYLD_INFO(_ONLY)` producer and the loader-finding disclosure.
/// Synthetic bytes only; every expectation is an exact `word(atSlot:)` answer.
final class MachODyldInfoInventoryTests: XCTestCase {
    private static let base: UInt64 = 0x1000
    private static let segmentSize = 0x400

    private struct Image {
        var rebase: [UInt8] = []
        var bind: [UInt8] = []
        var weak: [UInt8] = []
        var lazy: [UInt8] = []
        var words: [UInt64: UInt64] = [:]      // slot VA -> raw word
        var headerFlags: UInt32 = 0
        var sectionRelocations: UInt32 = 0
        var dysymtab: (ext: UInt32, local: UInt32)?
        var sections: [MachOSection] = []
        var infoCommandCount = 1
        var cache = false
    }

    private func inventory(_ image: Image) -> SwiftSlotInventory {
        var data = Data(count: Self.segmentSize)
        for (va, word) in image.words {
            let at = Int(va - Self.base)
            for i in 0..<8 { data[at + i] = UInt8(truncatingIfNeeded: word >> UInt64(8 * i)) }
        }
        func u32(_ value: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(8 * $0)) } }
        var commands: [MachOLoadCommand] = []
        var commandBytes: [UInt8] = []
        // Streams first so the command can point at them.
        var streamBytes: [UInt8] = []
        let streamStart = Self.segmentSize + 48 * 2 + 80
        func place(_ bytes: [UInt8]) -> (UInt32, UInt32) {
            let offset = streamStart + streamBytes.count
            streamBytes += bytes
            return (UInt32(offset), UInt32(bytes.count))
        }
        let r = place(image.rebase), b = place(image.bind), w = place(image.weak), l = place(image.lazy)
        for index in 0..<image.infoCommandCount {
            let offset = Self.segmentSize + 48 * index
            commands.append(MachOLoadCommand(command: 0x8000_0022, commandSize: 48, offset: UInt64(offset)))
            commandBytes += u32(0x8000_0022) + u32(48)
            commandBytes += u32(r.0) + u32(r.1) + u32(b.0) + u32(b.1) + u32(w.0) + u32(w.1) + u32(l.0) + u32(l.1)
            commandBytes += u32(0) + u32(0)
        }
        commandBytes += [UInt8](repeating: 0, count: 48 * (2 - image.infoCommandCount))
        var dysymtab = [UInt8](repeating: 0, count: 80)
        if let reloc = image.dysymtab {
            commands.append(MachOLoadCommand(command: 0xb, commandSize: 80,
                                             offset: UInt64(Self.segmentSize + 96)))
            dysymtab = u32(0xb) + u32(80) + [UInt8](repeating: 0, count: 60) + u32(reloc.ext)
                + [UInt8](repeating: 0, count: 4) + u32(reloc.local)
        }
        data.append(contentsOf: commandBytes + dysymtab + streamBytes)
        let segment = MachOSegment(name: "__DATA", vmAddress: Self.base, vmSize: UInt64(Self.segmentSize),
                                   fileOffset: 0, fileSize: UInt64(Self.segmentSize),
                                   maxProtection: 3, initialProtection: 3, sectionCount: 0, flags: 0)
        var sections = image.sections
        if image.sectionRelocations != 0 {
            sections.append(Self.section(address: Self.base, size: 8, flags: 0, relocations: image.sectionRelocations))
        }
        return MachOParser().buildSlotInventory(
            data: data,
            header: MachOHeader(magic: MachOConstants.machMagic64, cpuType: 0x0100_000c, cpuSubtype: 0, fileType: 6,
                                loadCommandCount: UInt32(commands.count), loadCommandsSize: 0,
                                flags: image.headerFlags, reserved: 0),
            loadCommands: commands, segments: [segment], sections: sections,
            dyldChainedFixups: nil, isCacheImage: image.cache)
    }

    private static func section(address: UInt64, size: UInt64, flags: UInt32, relocations: UInt32 = 0) -> MachOSection {
        MachOSection(sectionName: "__const", segmentName: "__DATA", address: address, size: size, fileOffset: 0,
                     alignment: 3, relocationOffset: 0, relocationCount: relocations, flags: flags,
                     reserved1: 0, reserved2: 0, reserved3: 0)
    }

    /// SET_SEGMENT_AND_OFFSET_ULEB for segment 0 and a slot VA (offsets below 0x4000).
    private func at(_ opcode: UInt8, _ va: UInt64) -> [UInt8] {
        let offset = va - Self.base
        return [opcode, UInt8(offset & 0x7f) | 0x80, UInt8(offset >> 7)]
    }

    // MARK: SPEC rows

    func testClassicRebaseBothSlotsAdmittedViaTargets() {          // SPEC 7
        var image = Image()
        image.words = [0x1180: 0xdead_0001, 0x1188: 0xdead_0002]
        image.rebase = [0x11] + at(0x20, 0x1180) + [0x52] + [0x00]     // two consecutive rebases
        let inv = inventory(image)
        XCTAssertEqual(inv.word(atSlot: 0x1180), .rebase(target: 0xdead_0001))
        XCTAssertEqual(inv.word(atSlot: 0x1188), .rebase(target: 0xdead_0002))
        XCTAssertEqual(inv.word(atSlot: 0x1100), .untouched)
    }

    func testClassicRebaseWordWithHighBitsIsNotAuthoritative() {    // FX-1257 F1
        // Dot item 1257 input: opcodes 11 20 80 03 51 00 (type 1, segment 0 offset 0x180, one rebase)
        // over owner word 0x0001_0000_0000_1100. Masking to 48 bits would forge the owner target 0x1100.
        var image = Image()
        image.words = [0x1180: 0x0001_0000_0000_1100]
        image.rebase = [0x11, 0x20, 0x80, 0x03, 0x51, 0x00]
        let inv = inventory(image)
        XCTAssertEqual(inv.word(atSlot: 0x1180), .occupied(.nonPointer),
                       "pointerWord(atSlot:) maps .occupied to nil, so no owner equality and no candidate admission")
        XCTAssertNotEqual(inv.word(atSlot: 0x1180), .rebase(target: 0x1100))

        // Control: the same stream over a word whose bits 48-63 are zero is still a proven rebase.
        var control = Image()
        control.words = [0x1180: 0x0000_0000_0000_1100]
        control.rebase = image.rebase
        XCTAssertEqual(inventory(control).word(atSlot: 0x1180), .rebase(target: 0x1100))
    }

    func testClassicZeroAddendBindWithholds() {                    // SPEC 8
        var image = Image()
        image.words = [0x1188: 0x2000, 0x1190: 0x2004]
        image.bind = [0x40] + Array("_sym".utf8) + [0, 0x51] + at(0x70, 0x1188) + [0x90, 0x00]
        image.rebase = [0x11] + at(0x20, 0x1190) + [0x51, 0x00]
        let inv = inventory(image)
        XCTAssertEqual(inv.word(atSlot: 0x1188), .occupied(.bind))
        XCTAssertEqual(inv.word(atSlot: 0x1190), .rebase(target: 0x2004))
    }

    func testClassicNonzeroAddendBindWithholds() {                  // SPEC 9 (the BLOCKED.md stream)
        for slot: UInt64 in [0x1188, 0x1180] {
            var image = Image()
            image.words = [slot: 0x2000, 0x1190: 0x2004]
            image.bind = [0x40, 0x5f, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x00, 0x51, 0x60, 0x08]
                + at(0x70, slot) + [0x90, 0x00]
            image.rebase = [0x11] + at(0x20, 0x1190) + [0x51, 0x00]
            let inv = inventory(image)
            XCTAssertEqual(inv.word(atSlot: slot), .occupied(.bind))
            XCTAssertEqual(inv.word(atSlot: 0x1190), .rebase(target: 0x2004))
        }
    }

    func testClassicUnresolvedBindOccupiesSlot() {                  // SPEC 10
        var image = Image()
        image.words = [0x1188: 0x2000]
        image.bind = [0x40, 0x00, 0x51] + at(0x70, 0x1188) + [0x90, 0x00]
        XCTAssertEqual(inventory(image).word(atSlot: 0x1188), .occupied(.bind))
    }

    func testClassicWeakAndLazyStreamsOccupy() {                    // SPEC 11
        var image = Image()
        image.words = [0x1188: 0x2000, 0x1190: 0x2000, 0x1198: 0x2000, 0x11a0: 0x2000]
        image.weak = [0x40, 0x5f, 0x77, 0x00, 0x51] + at(0x70, 0x1188) + [0x90, 0x00]
        // Lazy: DONE separates entries and must not cut the stream off.
        image.lazy = at(0x70, 0x1190) + [0x90, 0x00] + at(0x70, 0x1198) + [0x90, 0x00]
        let inv = inventory(image)
        XCTAssertEqual(inv.word(atSlot: 0x1188), .occupied(.weakLazy))
        XCTAssertEqual(inv.word(atSlot: 0x1190), .occupied(.weakLazy))
        XCTAssertEqual(inv.word(atSlot: 0x1198), .occupied(.weakLazy), "second lazy entry after DONE")
        XCTAssertEqual(inv.word(atSlot: 0x11a0), .untouched, "clean slot of a complete image")
        XCTAssertTrue(inv.withheld.isEmpty)
        var control = Image()
        control.words = [0x1188: 0x2000]
        XCTAssertEqual(inventory(control).word(atSlot: 0x1188), .untouched)
    }

    func testNarrowWritesOverlappingEightByteSlot() {                // SPEC 12
        var image = Image()
        // Type-2 rebases at 0x118c (slot+4), 0x11fc (slot-4 of 0x1200), and 0x1200 (equal start).
        image.rebase = [0x12] + at(0x20, 0x118c) + [0x51] + at(0x20, 0x11fc) + [0x51]
            + at(0x20, 0x1200) + [0x51, 0x00]
        let inv = inventory(image)
        XCTAssertEqual(inv.word(atSlot: 0x1188), .occupied(.narrowWrite))
        XCTAssertEqual(inv.word(atSlot: 0x11f8), .occupied(.narrowWrite))
        XCTAssertEqual(inv.word(atSlot: 0x1200), .occupied(.narrowWrite))
        XCTAssertEqual(inv.word(atSlot: 0x1180), .untouched)
    }

    func testClassicDuplicateAndCrossStreamConflict() {             // SPEC 13
        var image = Image()
        image.words = [0x1188: 0x2000, 0x1190: 0x2004, 0x1198: 0x2008, 0x11a0: 0x200c]
        image.rebase = [0x11] + at(0x20, 0x1188) + [0x51] + at(0x20, 0x1188) + [0x51]   // equal duplicate
            + at(0x20, 0x1190) + [0x51] + at(0x20, 0x1198) + [0x51, 0x00]
        image.bind = [0x40, 0x5f, 0x61, 0x00, 0x51] + at(0x70, 0x1198) + [0x90, 0x00]  // rebase + bind
        let inv = inventory(image)
        XCTAssertEqual(inv.word(atSlot: 0x1188), .ambiguous, "equal duplicates stay ambiguous")
        XCTAssertEqual(inv.word(atSlot: 0x1198), .ambiguous)
        XCTAssertEqual(inv.word(atSlot: 0x1190), .rebase(target: 0x2004))
        XCTAssertEqual(inv.word(atSlot: 0x11a0), .untouched)
    }

    func testClassicIncompleteStream() {                            // SPEC 14
        let maxULEB = [UInt8](repeating: 0xff, count: 10) + [0x01]
        let cases: [(String, Image, SwiftSlotInventory.Reason)] = [
            ("truncated ULEB", { var i = Image(); i.rebase = [0x11, 0x20, 0x80]; return i }(), .truncated),
            ("overlong ULEB", { var i = Image(); i.rebase = [0x11, 0x20] + maxULEB; return i }(), .malformedInventory),
            ("unsupported opcode", { var i = Image(); i.rebase = [0x11, 0xf0]; return i }(), .unsupportedOpcode),
            ("threaded opcode", { var i = Image(); i.bind = [0xd0]; return i }(), .unsupportedOpcode),
            ("segment out of range", { var i = Image(); i.rebase = [0x11, 0x29, 0x00, 0x51, 0x00]; return i }(),
             .malformedInventory),
            ("budget exhaustion", { var i = Image(); i.rebase = [0x11, 0x20, 0x00, 0x60] + [0xc1, 0x84, 0x3d, 0x00]; return i }(),
             .budget),
            ("unsupported bind type", { var i = Image(); i.bind = [0x40, 0x61, 0x00, 0x55] + [0x70, 0x00, 0x90, 0x00]; return i }(),
             .unsupportedFormat),
        ]
        for (label, var image, reason) in cases {
            // A rebase and a bind seen before the failure.
            image.words[0x1180] = 0x2000
            image.words[0x1188] = 0x2000
            if label == "unsupported bind type" || label == "threaded opcode" {
                image.rebase = [0x11] + at(0x20, 0x1180) + [0x51, 0x00]
            } else {
                image.bind = [0x40, 0x61, 0x00, 0x51] + at(0x70, 0x1188) + [0x90, 0x00]
                image.rebase = [0x11] + at(0x20, 0x1180) + [0x51] + image.rebase.dropFirst().map { $0 }
            }
            let inv = inventory(image)
            XCTAssertEqual(inv.word(atSlot: 0x1100), .uninspected(reason), label)
            XCTAssertEqual(inv.word(atSlot: 0x1180), .uninspected(reason), "\(label): earlier rebase is not R")
            XCTAssertEqual(inv.withheld.map(\.scope), [.classicImage], label)
        }
        // Events seen before the failure stay visible (occupied beats uninspected).
        var image = Image()
        image.bind = [0x40, 0x61, 0x00, 0x51] + at(0x70, 0x1188) + [0x90, 0x00]
        image.rebase = [0x11, 0xf0]
        XCTAssertEqual(inventory(image).word(atSlot: 0x1188), .occupied(.bind))
    }

    func testSlotWidthBoundary() {                                  // SPEC 25
        let inv = inventory(Image())
        XCTAssertEqual(inv.word(atSlot: 0x13f8), .untouched)
        XCTAssertEqual(inv.word(atSlot: 0x13fc), .uninspected(.outsideCoverage), "straddles the segment end")
        XCTAssertEqual(inv.word(atSlot: 0x0ffc), .uninspected(.outsideCoverage), "straddles the segment start")
    }

    func testRelocationsBlockTheImage() {                           // SPEC 32-34 under R-Q4b
        var section = Image()
        section.sectionRelocations = 1
        var external = Image()
        external.dysymtab = (ext: 1, local: 0)
        var local = Image()
        local.dysymtab = (ext: 0, local: 2)
        for image in [section, external, local] {
            let inv = inventory(image)
            XCTAssertEqual(inv.word(atSlot: 0x1188), .uninspected(.relocation))
            XCTAssertEqual(inv.withheld.map(\.scope), [.relocations])
        }
    }

    func testEmptyRelocationTablesKeepWitness() {                   // SPEC 35
        var image = Image()
        image.words = [0x1188: 0x2000]
        image.dysymtab = (ext: 0, local: 0)
        XCTAssertEqual(inventory(image).word(atSlot: 0x1188), .untouched)
    }

    func testDeclarationBlockers() {
        var duplicate = Image()
        duplicate.infoCommandCount = 2
        XCTAssertEqual(inventory(duplicate).word(atSlot: 0x1188), .uninspected(.duplicateDeclaration))
        var cache = Image()
        cache.headerFlags = 0x8000_0000
        XCTAssertEqual(inventory(cache).word(atSlot: 0x1188), .uninspected(.cacheImage))
        var cacheContext = Image()
        cacheContext.cache = true
        XCTAssertEqual(inventory(cacheContext).withheld.map(\.scope), [.cacheWithheld])
        var indirect = Image()
        indirect.sections = [Self.section(address: 0x1200, size: 0x10, flags: 0x6)]   // S_NON_LAZY_SYMBOL_POINTERS
        let inv = inventory(indirect)
        XCTAssertEqual(inv.word(atSlot: 0x1200), .occupied(.indirectPointer))
        XCTAssertEqual(inv.word(atSlot: 0x1188), .untouched)
    }

    func testProducerStampsSliceExtent() {
        let inv = inventory(Image())
        XCTAssertNotNil(inv.extent)
        XCTAssertEqual(inv.attested(sliceOffset: 0, sliceSize: UInt64(inv.extent?.size ?? 0)).word(atSlot: 0x1188), .untouched)
        XCTAssertEqual(inv.attested(sliceOffset: 0x4000, sliceSize: inv.extent?.size ?? 0).word(atSlot: 0x1188),
                       .uninspected(.extentMismatch))
    }

    // MARK: disclosure (R-Q11)

    func testWithheldScopesAreDisclosedAsLoaderFindings() {
        var unsupported = Image(); unsupported.rebase = [0x11, 0xf0]
        var relocations = Image(); relocations.sectionRelocations = 1
        var cache = Image(); cache.cache = true
        var missing = Image(); missing.infoCommandCount = 2
        let expected: [(Image, String, String)] = [
            (unsupported, "classic-image", "unsupportedOpcode"),
            (relocations, "relocations", "relocation"),
            (cache, "cache-withheld", "cacheImage"),
            (missing, "image-declaration", "duplicateDeclaration"),
        ]
        for (image, scope, reason) in expected {
            let findings = LoaderFinding.slotInventoryFindings(inventory(image), hasWitnessMetadata: true)
            XCTAssertEqual(findings.count, 1, scope)
            XCTAssertEqual(findings.first?.code, "swiftWitnessSlotInventoryIncomplete", scope)
            XCTAssertEqual(findings.first?.category, .metadataParseIssue, scope)
            XCTAssertTrue(findings.first?.message.contains("scope=\(scope) reason=\(reason)") == true, scope)
            XCTAssertTrue(LoaderFinding.slotInventoryFindings(inventory(image), hasWitnessMetadata: false).isEmpty,
                          "no witness metadata, nothing withheld")
        }
        // A fully proven image discloses nothing.
        XCTAssertTrue(LoaderFinding.slotInventoryFindings(inventory(Image()), hasWitnessMetadata: true).isEmpty)
        // The cache projection loader path uses the same code.
        let cacheFinding = LoaderFinding.cacheWithheldFinding(address: 0x1234)
        XCTAssertEqual(cacheFinding.code, "swiftWitnessSlotInventoryIncomplete")
        XCTAssertTrue(cacheFinding.message.contains("scope=cache-withheld reason=cacheImage"))
        // Per-scope findings are capped and summarised by count.
        var many = SwiftSlotInventory.Builder()
        for i in 0..<70 { many.note(.chainedPage, .multiStart, extent: UInt64(i) * 0x1000..<UInt64(i + 1) * 0x1000) }
        let capped = LoaderFinding.slotInventoryFindings(many.build(extent: nil), hasWitnessMetadata: true)
        XCTAssertEqual(capped.count, 65)
        XCTAssertTrue(capped.last?.message.contains("6 further scopes") == true)
    }

    func testHandBuiltLoadedBinaryDefaultsToUnknown() {            // pins the contract for synthetic callers
        let text = BinarySection(name: "__text", address: 0x1000, size: 0x10, fileOffset: 0,
                                 isExecutable: true, fileSize: 0x10)
        let binary = LoadedBinary(
            name: "hand-built", path: "", isBundle: false, cpuType: MachOConstants.cpuTypeARM64,
            fileTypeName: "fixture", architectureDisplayName: "arm64", metadata: .empty,
            bytes: Data(count: 0x10), sliceOffset: 0, sliceSize: 0x10, sections: [text],
            executableTextSection: text, entryPointAddress: 0x1000, symbols: [], imports: [],
            indirectSymbols: [], exports: [], stringLiterals: [], functionStarts: [], objcSelectors: [:])
        XCTAssertEqual(binary.swiftSlotInventory, .unknown)
        XCTAssertEqual(binary.swiftSlotInventory.word(atSlot: 0x1188), .uninspected(.unknownProducer))
        XCTAssertTrue(binary.swiftSlotInventory.withheld.isEmpty)
    }
}
