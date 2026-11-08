import Foundation
import XCTest
@testable import MacScope

/// FX-SLOT slice C: the chained-fixup producer and the shared page walker.
/// Synthetic images only. Segment `i` sits at VA `textBase + fileOffset`, so file offset and VA differ
/// by a constant. Every expectation is an exact `word(atSlot:)` answer.
final class ChainedSlotInventoryTests: XCTestCase {
    private static let textBase: UInt64 = 0x10000
    private static let page: UInt64 = 0x1000

    private typealias Entry = (offset: UInt16, kind: MachOChainedFixupKind)

    private struct Seg {
        var name = "__DATA"
        var pages: [[Entry]]
        var hasRecord = true
        var format: UInt16 = MachOConstants.dyldChainedPtr64
    }

    private struct Built {
        var data: Data
        var header: MachODyldChainedFixups
        var segments: [MachOSegment]
        var startsAt: Int
        var recordAt: [Int: Int]     // segment index -> absolute data offset of its starts_in_segment

        func va(segment: Int, page: Int, offset: UInt16) -> UInt64 {
            segments[segment].vmAddress + UInt64(page) * ChainedSlotInventoryTests.page + UInt64(offset)
        }
        func fileOffset(segment: Int, page: Int, offset: UInt16) -> Int {
            Int(segments[segment].fileOffset) + page * 0x1000 + Int(offset)
        }
    }

    private static func put(_ value: UInt64, width: Int, at: Int, into data: inout Data) {
        for i in 0..<width { data[at + i] = UInt8(truncatingIfNeeded: value >> UInt64(8 * i)) }
    }

    private static func isArm(_ format: UInt16) -> Bool {
        [MachOConstants.dyldChainedPtrArm64e, MachOConstants.dyldChainedPtrArm64eUserland,
         MachOConstants.dyldChainedPtrArm64eUserland24].contains(format)
    }

    private static func rebase(_ target: UInt64) -> MachOChainedFixupKind { .rebase(targetAddress: target) }
    private static let namedBind = MachOChainedFixupKind.bind(importOrdinal: 1, symbolName: "_sym", addend: 0)

    /// Segment 0 is an empty `__TEXT` (no starts record); `specs` become segments 1...
    private static func build(_ specs: [Seg]) -> Built {
        var segments = [MachOSegment(name: "__TEXT", vmAddress: textBase, vmSize: page, fileOffset: 0, fileSize: page,
                                     maxProtection: 5, initialProtection: 5, sectionCount: 0, flags: 0)]
        var cursor = page
        for spec in specs {
            let size = UInt64(spec.pages.count) * page
            segments.append(MachOSegment(name: spec.name, vmAddress: textBase + cursor, vmSize: size,
                                         fileOffset: cursor, fileSize: size, maxProtection: 3,
                                         initialProtection: 3, sectionCount: 0, flags: 0))
            cursor += size
        }
        var data = Data(count: Int(cursor))
        var fixups: [MachOChainedFixup] = []
        for (i, spec) in specs.enumerated() {
            let segment = segments[i + 1]
            let arm = isArm(spec.format)
            let stride = arm ? 8 : 4
            for (p, entries) in spec.pages.enumerated() {
                let sorted = entries.sorted { $0.offset < $1.offset }
                for (k, entry) in sorted.enumerated() {
                    let offset = Int(segment.fileOffset) + p * 0x1000 + Int(entry.offset)
                    let next = k + 1 < sorted.count ? UInt64((Int(sorted[k + 1].offset) - Int(entry.offset)) / stride) : 0
                    var raw: UInt64 = 0x1234 | (next << 51)
                    if case .bind = entry.kind { raw |= arm ? (1 << 62) : (1 << 63) }
                    if arm { raw |= 1 << 63 }   // arm64e: the authentication bit is set on every raw word
                    put(raw, width: 8, at: offset, into: &data)
                    fixups.append(MachOChainedFixup(
                        fileOffset: UInt64(offset), address: segment.vmAddress + UInt64(p * 0x1000) + UInt64(entry.offset),
                        pointerFormat: spec.format, kind: entry.kind))
                }
            }
        }
        // Payload: 28-byte header area, starts at +32, then the records.
        let payloadStart = data.count
        let startsAt = payloadStart + 32
        let count = segments.count
        var running = 4 + 4 * count
        var recordAt: [Int: Int] = [:]
        var layout: [(Int, Int, Seg)] = []
        for (i, spec) in specs.enumerated() where spec.hasRecord {
            let size = (22 + 2 * spec.pages.count + 3) & ~3
            layout.append((i + 1, running, spec))
            recordAt[i + 1] = startsAt + running
            running += size
        }
        data.append(Data(count: 32 + running + 16))
        put(UInt64(count), width: 4, at: startsAt, into: &data)
        for (index, relative, spec) in layout {
            put(UInt64(relative), width: 4, at: startsAt + 4 + 4 * index, into: &data)
            let at = startsAt + relative
            let size = (22 + 2 * spec.pages.count + 3) & ~3
            put(UInt64(size), width: 4, at: at, into: &data)
            put(0x1000, width: 2, at: at + 4, into: &data)
            put(UInt64(spec.format), width: 2, at: at + 6, into: &data)
            put(segments[index].vmAddress - textBase, width: 8, at: at + 8, into: &data)
            put(UInt64(spec.pages.count), width: 2, at: at + 20, into: &data)
            for (p, entries) in spec.pages.enumerated() {
                let first = entries.map(\.offset).min() ?? 0xffff
                put(UInt64(first), width: 2, at: at + 22 + 2 * p, into: &data)
            }
        }
        let header = MachODyldChainedFixups(
            dataOffset: UInt32(payloadStart), dataSize: UInt32(32 + running + 16), fixupsVersion: 0,
            startsOffset: 32, importsOffset: UInt32(32 + running), symbolsOffset: UInt32(32 + running),
            importsCount: 0, importsFormat: 1, symbolsFormat: 0, imports: [], fixups: fixups)
        return Built(data: data, header: header, segments: segments, startsAt: startsAt, recordAt: recordAt)
    }

    private func inventory(_ built: Built) -> SwiftSlotInventory {
        var builder = SwiftSlotInventory.Builder()
        return MachOParser().buildChainedSlotInventory(
            &builder, data: built.data,
            extent: .init(offset: 0, size: UInt64(built.data.count)),
            segments: built.segments, dyldChainedFixups: built.header)
    }

    private func isUninspected(_ word: SwiftSlotInventory.Word) -> Bool {
        if case .uninspected = word { return true }
        return false
    }

    // MARK: SPEC rows

    func testChainedRebasePositive() {                              // SPEC 15
        let built = Self.build([Seg(pages: [[(0x180, Self.rebase(0x5000_0001)), (0x188, Self.rebase(0x5000_0002))], []])])
        let inv = inventory(built)
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x180)), .rebase(target: 0x5000_0001),
                       "decoded target replaces the raw chain-encoded word")
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x188)), .rebase(target: 0x5000_0002))
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x190)), .untouched)
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 1, offset: 0x10)), .untouched,
                       "an empty page (0xffff) with no decoded fixup is covered")
        XCTAssertEqual(inv.word(atSlot: Self.textBase + 0x10), .untouched, "starts-less segment without fixups is covered")
        XCTAssertTrue(inv.withheld.isEmpty)
    }

    func testChainedAllBindFormsOccupy() {                          // SPEC 16
        let unnamed = MachOChainedFixupKind.bind(importOrdinal: 99, symbolName: nil, addend: 0)
        let addend = MachOChainedFixupKind.bind(importOrdinal: 1, symbolName: "_sym", addend: 8)
        let built = Self.build([Seg(pages: [[(0x10, Self.namedBind), (0x18, addend), (0x20, unnamed),
                                               (0x28, Self.rebase(0x7000))]])])
        let inv = inventory(built)
        for offset: UInt16 in [0x10, 0x18, 0x20] {
            XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: offset)), .occupied(.bind),
                           "bind at \(offset)")
        }
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x28)), .rebase(target: 0x7000))

        // arm64e layout-only block: the raw words carry the auth bit and the decoded kinds are hand-authored here, so no authentication decode is tested.
        // Byte-level authenticated cases are in MachOAuthenticatedChainedBytesTests.
        let arm64eLayoutOnlyBuilt = Self.build([Seg(pages: [[(0x10, Self.namedBind), (0x18, Self.rebase(0x7100))]],
                                  format: MachOConstants.dyldChainedPtrArm64e)])
        let arm64eLayoutOnlyInventory = inventory(arm64eLayoutOnlyBuilt)
        XCTAssertEqual(arm64eLayoutOnlyInventory.word(atSlot: arm64eLayoutOnlyBuilt.va(segment: 1, page: 0, offset: 0x10)), .occupied(.bind))
        XCTAssertEqual(arm64eLayoutOnlyInventory.word(atSlot: arm64eLayoutOnlyBuilt.va(segment: 1, page: 0, offset: 0x18)), .rebase(target: 0x7100))
    }

    func testChainedDuplicateSourceIdentity() {                     // SPEC 17
        // Two decoded fixups for one VA: ambiguous, and the page is not covered. A distinct segment stays R.
        var built = Self.build([Seg(name: "__A", pages: [[(0x10, Self.rebase(1)), (0x20, Self.rebase(2))]]),
                                Seg(name: "__B", pages: [[(0x10, Self.rebase(3))]])])
        let dup = built.header.fixups[0]
        built.header.fixups.append(dup)
        var inv = inventory(built)
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x10)), .ambiguous)
        XCTAssertTrue(isUninspected(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x20))),
                      "the conflicted page is withheld, so the neighbouring rebase is not R")
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 2, page: 0, offset: 0x10)), .rebase(target: 3))

        // Overlapping starts_in_segment extents: both scopes are conflicted; no record decides.
        var overlap = Self.build([Seg(name: "__A", pages: [[(0x10, Self.rebase(1))]]),
                                  Seg(name: "__B", pages: [[(0x10, Self.rebase(3))]]),
                                  Seg(name: "__C", pages: [[(0x10, Self.rebase(5))]])])
        let aSize = 0x20
        Self.put(UInt64(aSize), width: 4, at: overlap.recordAt[1]!, into: &overlap.data)   // A now spans B's record
        inv = inventory(overlap)
        XCTAssertTrue(isUninspected(inv.word(atSlot: overlap.va(segment: 1, page: 0, offset: 0x10))))
        XCTAssertTrue(isUninspected(inv.word(atSlot: overlap.va(segment: 2, page: 0, offset: 0x10))))
        XCTAssertEqual(inv.word(atSlot: overlap.va(segment: 3, page: 0, offset: 0x10)), .rebase(target: 5))
        XCTAssertEqual(inv.withheld.filter { $0.reason == .duplicate }.count, 2)
    }

    func testChainedPartialInventory() {                            // SPEC 18
        func twoSegments() -> Built {
            Self.build([Seg(name: "__BAD", pages: [[(0x10, Self.rebase(1)), (0x20, Self.rebase(2))]]),
                        Seg(name: "__CLEAN", pages: [[(0x10, Self.rebase(9))]])])
        }
        func assertAffected(_ built: Built, _ name: String, line: UInt = #line) {
            let inv = inventory(built)
            XCTAssertTrue(isUninspected(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x10)))
                          || inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x10)) == .ambiguous,
                          "\(name): affected scope must not be R", line: line)
            XCTAssertTrue(isUninspected(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x30))),
                          "\(name): untouched is not proven", line: line)
            XCTAssertEqual(inv.word(atSlot: built.va(segment: 2, page: 0, offset: 0x10)), .rebase(target: 9),
                           "\(name): clean segment survives", line: line)
            XCTAssertFalse(inv.withheld.isEmpty, name, line: line)
        }

        var unsupported = twoSegments()
        Self.put(0xffff, width: 2, at: unsupported.recordAt[1]! + 6, into: &unsupported.data)
        assertAffected(unsupported, "unsupported pointer format")

        var truncated = twoSegments()
        Self.put(0xffff_fff0, width: 4, at: truncated.startsAt + 4 + 4 * 1, into: &truncated.data)
        assertAffected(truncated, "segment record outside payload")

        var badDelta = twoSegments()   // first link claims a next delta that leaves the page
        let rawAt = badDelta.fileOffset(segment: 1, page: 0, offset: 0x10)
        Self.put(0x1234 | (UInt64(0xfff) << 51), width: 8, at: rawAt, into: &badDelta.data)
        assertAffected(badDelta, "malformed next delta")

        var omitted = twoSegments()    // a chain link the decoder did not report
        let omittedVA = omitted.va(segment: 1, page: 0, offset: 0x20)
        omitted.header.fixups.removeAll { $0.address == omittedVA }
        assertAffected(omitted, "omitted decoded fixup")

        var extra = twoSegments()      // a decoded fixup on a page whose starts entry says empty
        Self.put(0xffff, width: 2, at: extra.recordAt[1]! + 22, into: &extra.data)
        assertAffected(extra, "decoded fixup on an empty page")

        var badStarts = twoSegments()  // invalid starts offset: nothing is inspected image-wide
        badStarts.header.startsOffset = 0x7fff_0000
        let wide = inventory(badStarts)
        XCTAssertTrue(isUninspected(wide.word(atSlot: badStarts.va(segment: 2, page: 0, offset: 0x30))))
        XCTAssertEqual(wide.withheld.first?.scope, .chainedPage)

        var capped = twoSegments()
        capped.header.fixups = Array(repeating: capped.header.fixups[0], count: SwiftSlotInventory.maxEvents + 1)
        let cap = inventory(capped)
        XCTAssertTrue(isUninspected(cap.word(atSlot: capped.va(segment: 2, page: 0, offset: 0x30))))
        XCTAssertEqual(cap.withheld.map(\.scope), [.cap])
        XCTAssertEqual(cap.withheld.first?.reason, .budget)
    }

    func testHostileSegmentGeometryRefusesWithoutTrapping() {       // FX-1257 F2
        // A: vmAddress 0xffff_ffff_ffff_f800, vmSize 0x100 (span end does not overflow, pageVA + pageSize does).
        var a = Self.build([Seg(pages: [[(0x10, Self.rebase(0x5000))]])])
        let vmAddress: UInt64 = 0xffff_ffff_ffff_f800
        a.segments[1].vmAddress = vmAddress
        a.segments[1].vmSize = 0x100
        a.segments[1].fileSize = 0x100   // keeps vmAddress + max(vmSize, fileSize) from overflowing
        Self.put(vmAddress - Self.textBase, width: 8, at: a.recordAt[1]! + 8, into: &a.data)
        let invA = inventory(a)
        XCTAssertTrue(isUninspected(invA.word(atSlot: vmAddress + 0x10)), "page-end overflow withholds the page")
        XCTAssertEqual(invA.withheld.first?.scope, .chainedPage)
        XCTAssertEqual(invA.withheld.first?.reason, .malformedInventory)

        // B: fileOffset UInt64.max - 7 (the segment record is otherwise valid).
        var b = Self.build([Seg(pages: [[(0x10, Self.rebase(0x5000))]])])
        b.segments[1].fileOffset = UInt64.max - 7
        let invB = inventory(b)
        XCTAssertTrue(isUninspected(invB.word(atSlot: b.va(segment: 1, page: 0, offset: 0x10))),
                      "file-offset overflow withholds the page")
        XCTAssertEqual(invB.withheld.first?.scope, .chainedPage)
        XCTAssertEqual(invB.withheld.first?.reason, .malformedInventory)

        // The shared walker refuses the same geometry directly.
        var visited = Set<UInt64>()
        XCTAssertThrowsError(try MachOParser().walkChainedPage(
            data: b.data, segment: b.segments[1], pageSize: 0x1000, pageOffset: 0, first: 0x10,
            format: MachOConstants.dyldChainedPtr64, visited: &visited) { _ in }) {
            XCTAssertEqual($0 as? ChainedPageWalkIssue, .malformed)
        }
    }

    func testChainedMultiStartIsUninspected() {                     // SPEC 19 (deferred loss, R-Q5)
        var built = Self.build([Seg(pages: [[(0x10, Self.rebase(1))], [(0x10, Self.rebase(2))]])])
        Self.put(0x8001, width: 2, at: built.recordAt[1]! + 22 + 2, into: &built.data)    // page 1 is multi-start
        let inv = inventory(built)
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x10)), .rebase(target: 1))
        XCTAssertTrue(isUninspected(inv.word(atSlot: built.va(segment: 1, page: 1, offset: 0x10))))
        XCTAssertTrue(isUninspected(inv.word(atSlot: built.va(segment: 1, page: 1, offset: 0x80))))
        XCTAssertEqual(inv.withheld.map(\.scope), [.multiStart])
        XCTAssertEqual(inv.withheld.first?.reason, .multiStart)
    }

    func testUnrelatedBindDoesNotEraseProvenRebase() {              // SPEC 20
        let addend = MachOChainedFixupKind.bind(importOrdinal: 1, symbolName: "_w", addend: 4)
        let built = Self.build([Seg(pages: [[(0x180, Self.rebase(0x4242))], [(0x40, addend)]])])
        let inv = inventory(built)
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x180)), .rebase(target: 0x4242))
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 1, offset: 0x40)), .occupied(.bind))
    }

    func testChainedSlotWidthBoundary() {                           // SPEC 25
        var built = Self.build([Seg(pages: [[(0x10, Self.rebase(1))], [(0x10, Self.rebase(2))]])])
        Self.put(0x8001, width: 2, at: built.recordAt[1]! + 22 + 2, into: &built.data)    // page 1 withheld
        let inv = inventory(built)
        let segmentEnd = built.segments[1].vmAddress + built.segments[1].vmSize
        let pageEnd = built.segments[1].vmAddress + 0x1000
        XCTAssertEqual(inv.word(atSlot: pageEnd - 8), .untouched)
        XCTAssertTrue(isUninspected(inv.word(atSlot: pageEnd - 4)), "straddles into the withheld page")
        XCTAssertTrue(isUninspected(inv.word(atSlot: segmentEnd - 4)), "straddles the segment end")
    }

    func testWalkerSharedGeometry() throws {                        // SPEC row R-Q9 parity
        let built = Self.build([Seg(pages: [[(0x10, Self.rebase(1)), (0x18, Self.rebase(2)), (0x40, Self.rebase(3))]])])
        let parser = MachOParser()
        var visited = Set<UInt64>()
        var seen: [UInt64] = []
        try parser.walkChainedPage(data: built.data, segment: built.segments[1], pageSize: 0x1000, pageOffset: 0,
                                   first: 0x10, format: MachOConstants.dyldChainedPtr64, visited: &visited) {
            seen.append($0.fileOffset)
            XCTAssertEqual($0.address - built.segments[1].vmAddress, $0.fileOffset - built.segments[1].fileOffset)
        }
        XCTAssertEqual(seen, built.header.fixups.map(\.fileOffset), "walker visits exactly the decoded fixups")
        func issue(_ data: Data, _ visited: inout Set<UInt64>) -> ChainedPageWalkIssue? {
            do {
                try parser.walkChainedPage(data: data, segment: built.segments[1], pageSize: 0x1000, pageOffset: 0,
                                           first: 0x10, format: MachOConstants.dyldChainedPtr64,
                                           visited: &visited) { _ in }
            } catch let error as ChainedPageWalkIssue {
                return error
            } catch {
                return nil
            }
            return nil
        }
        // A second walk over the same links is a revisit.
        XCTAssertEqual(issue(built.data, &visited), .malformed)
        // A delta shorter than one slot is malformed.
        var short = built
        Self.put(0x1234 | (UInt64(1) << 51), width: 8, at: built.fileOffset(segment: 1, page: 0, offset: 0x10),
                 into: &short.data)
        var fresh = Set<UInt64>()
        XCTAssertEqual(issue(short.data, &fresh), .malformed)
    }

    func testBuildSlotInventoryDispatchesChainedImages() {
        let built = Self.build([Seg(pages: [[(0x10, Self.rebase(0x77))]])])
        let command = MachOLoadCommand(command: 0x8000_0034, commandSize: 16, offset: 0)
        let inv = MachOParser().buildSlotInventory(
            data: built.data,
            header: MachOHeader(magic: MachOConstants.machMagic64, cpuType: 0x0100_000c, cpuSubtype: 0, fileType: 6,
                                loadCommandCount: 1, loadCommandsSize: 16, flags: 0, reserved: 0),
            loadCommands: [command], segments: built.segments, sections: [],
            dyldChainedFixups: built.header, isCacheImage: false)
        XCTAssertEqual(inv.word(atSlot: built.va(segment: 1, page: 0, offset: 0x10)), .rebase(target: 0x77))
        XCTAssertEqual(inv.extent, SwiftSlotInventory.Extent(offset: 0, size: UInt64(built.data.count)))

        let missing = MachOParser().buildSlotInventory(
            data: built.data,
            header: MachOHeader(magic: MachOConstants.machMagic64, cpuType: 0x0100_000c, cpuSubtype: 0, fileType: 6,
                                loadCommandCount: 1, loadCommandsSize: 16, flags: 0, reserved: 0),
            loadCommands: [command], segments: built.segments, sections: [],
            dyldChainedFixups: nil, isCacheImage: false)
        XCTAssertTrue(isUninspected(missing.word(atSlot: built.va(segment: 1, page: 0, offset: 0x10))))
        XCTAssertEqual(missing.withheld.first?.scope, .chainedPage)
        XCTAssertEqual(missing.withheld.first?.reason, .unsupportedFormat)
    }

    // MARK: R-Q11 disclosure

    func testChainedWithheldScopesAreDisclosedAsLoaderFindings() {
        var multi = Self.build([Seg(pages: [[(0x10, Self.rebase(1))]])])
        Self.put(0x8001, width: 2, at: multi.recordAt[1]! + 22, into: &multi.data)
        var badPage = Self.build([Seg(pages: [[(0x10, Self.rebase(1))]])])
        Self.put(0xffff, width: 2, at: badPage.recordAt[1]! + 22, into: &badPage.data)
        var capped = Self.build([Seg(pages: [[(0x10, Self.rebase(1))]])])
        capped.header.fixups = Array(repeating: capped.header.fixups[0], count: SwiftSlotInventory.maxEvents + 1)
        var unsupported = Self.build([Seg(pages: [[(0x10, Self.rebase(1))]])])
        unsupported.header.importsFormat = 9

        let expected: [(Built, String, String)] = [
            (multi, "multi-start", "multiStart"),
            (badPage, "chained-page", "malformedInventory"),
            (capped, "cap", "budget"),
            (unsupported, "chained-page", "unsupportedFormat"),
        ]
        for (built, scope, reason) in expected {
            let findings = LoaderFinding.slotInventoryFindings(inventory(built), hasWitnessMetadata: true)
            XCTAssertEqual(findings.count, 1, scope)
            XCTAssertEqual(findings.first?.code, "swiftWitnessSlotInventoryIncomplete", scope)
            XCTAssertEqual(findings.first?.category, .metadataParseIssue, scope)
            XCTAssertTrue(findings.first?.message.contains("scope=\(scope) reason=\(reason)") == true,
                          "\(scope): \(findings.first?.message ?? "none")")
        }
        // A clean chained image discloses nothing.
        let clean = Self.build([Seg(pages: [[(0x10, Self.rebase(1))]])])
        XCTAssertTrue(LoaderFinding.slotInventoryFindings(inventory(clean), hasWitnessMetadata: true).isEmpty)
    }
}
