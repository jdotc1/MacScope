import Foundation
import XCTest
@testable import MacScope

/// Authored, unrun controls over synthetic bytes; no authentication operation occurs.
/// Uses the real parser and its returned inventory, never hand-authored decoded fixups.
final class MachOAuthenticatedChainedBytesTests: XCTestCase {
    private let imageBase: UInt64 = 0x2_0000_0000
    private let authBit: UInt64 = UInt64(1) << 63
    private let rebaseRaw: UInt64 = (UInt64(1) << 63) | (UInt64(1) << 32) | 0x120

    /// Offsets come from fixture geometry, independently of any parser output.
    /// Fixture.swift:1032-1033,1230-1231 establish address = imageBase + file offset.
    private func offset(of address: UInt64, in bytes: Data) throws -> Int {
        let (relative, underflow) = address.subtractingReportingOverflow(imageBase)
        XCTAssertFalse(underflow, "fixture address precedes image base")
        guard !underflow else { throw FixtureIssue.invalidOffset }
        let at = try XCTUnwrap(Int(exactly: relative))
        guard at >= 0, at <= bytes.count, bytes.count - at >= 8 else {
            XCTFail("fixture pointer does not fit the byte buffer")
            throw FixtureIssue.invalidOffset
        }
        return at
    }

    private enum FixtureIssue: Error { case invalidOffset }

    /// Bounded, local little-endian readback; offset() establishes the eight-byte extent.
    private func assertInjected(_ expected: UInt64, at address: UInt64, in bytes: Data) throws {
        let at = try offset(of: address, in: bytes)
        var actual: UInt64 = 0
        for byte in 0..<8 {
            actual |= UInt64(bytes[bytes.startIndex + at + byte]) << (8 * byte)
        }
        // Fixture preconditions: CANNOT-FAIL from a decoder-only mutation.
        XCTAssertEqual(actual, expected, "the bytes, not merely the source value, must match")
        XCTAssertNotEqual(actual & authBit, 0, "bit 63 must really be present in the bytes")
    }

    private func authenticatedFixture(format: UInt16, ordinal: Int = 0) throws
        -> (fixture: MachOFixture, bytes: Data) {
        let fixture = MachOFixture.makeExecutableWithChainedFixupChain(
            imageBase: imageBase, pointerFormat: format,
            rebaseRawOverride: rebaseRaw, importCount: ordinal + 1
        )
        var bytes = fixture.bytes
        // One arm64e stride reaches the second word. Bit 32 is auth metadata;
        // if auth bit 63 is ignored, it becomes a nonzero plain-bind addend.
        let bindRaw = authBit | (UInt64(1) << 62) | (UInt64(1) << 51)
            | (UInt64(1) << 32) | UInt64(ordinal)
        let bindOffset = try offset(of: fixture.chainedBindAddress, in: bytes)
        MachOFixture.writeUInt64LE(&bytes, at: bindOffset, value: bindRaw)
        try assertInjected(bindRaw, at: fixture.chainedBindAddress, in: bytes)
        try assertInjected(rebaseRaw, at: fixture.chainedRebaseAddress, in: bytes)
        return (fixture, bytes)
    }

    func testAuthenticatedChainedBytesReachInventoryThroughParser() throws {
        for format: UInt16 in [1, 9, 12] {
            let input = try authenticatedFixture(format: format)
            let parsed = try MachOParser().parse(input.bytes)
            let chained = try XCTUnwrap(parsed.dyldChainedFixups)
            // Structural guards: can fail on wrong next/stride or dropped entries;
            // CANNOT-FAIL for a mutation confined to the decoded target value.
            XCTAssertEqual(chained.fixups.count, 2, "format \(format)")
            let rebase = try XCTUnwrap(chained.fixups.first {
                $0.address == input.fixture.chainedRebaseAddress
            })
            XCTAssertEqual(rebase.pointerFormat, format)
            let expected = imageBase + (rebaseRaw & 0xffff_ffff)
            // Can fail: ignoring bit 63 yields 0x1_0000_0120 for format 1,
            // and 0x3_0000_0120 for formats 9/12, rather than 0x2_0000_0120.
            guard case .rebase(let target) = rebase.kind else {
                XCTFail("authenticated raw rebase was not decoded as a rebase: \(format)")
                continue
            }
            XCTAssertEqual(target, expected, "format \(format)")
            // Can fail on the same auth-bit mutation; no inventory fallback is accepted.
            XCTAssertEqual(parsed.swiftSlotInventory.word(atSlot: input.fixture.chainedRebaseAddress),
                           .rebase(target: expected), "format \(format)")
        }
    }

    func testAuthenticatedChainedBindBytesReachInventoryThroughParser() throws {
        for format: UInt16 in [1, 9, 12] {
            // Fixture.swift:1114-1116 supplies the distinct name at index 65536.
            // USERLAND24 must preserve ordinal bit 16 rather than alias index zero.
            let expectedOrdinal = format == 12 ? 65_536 : 0
            let expectedName = format == 12 ? "_ordinal65536" : "_puts"
            let input = try authenticatedFixture(format: format, ordinal: expectedOrdinal)
            let parsed = try MachOParser().parse(input.bytes)
            let chained = try XCTUnwrap(parsed.dyldChainedFixups)
            // Structural: can fail on next/stride loss, not an addend-only mutation.
            XCTAssertEqual(chained.fixups.count, 2, "format \(format)")
            let bind = try XCTUnwrap(chained.fixups.first {
                $0.address == input.fixture.chainedBindAddress
            })
            XCTAssertEqual(bind.pointerFormat, format)
            // Can fail if bind bit 62 is ignored; never constructs a decoded kind.
            guard case .bind(let ordinal, let name, let addend) = bind.kind else {
                XCTFail("authenticated raw bind was not decoded as a bind: \(format)")
                continue
            }
            // Can fail if ordinal bit 16 is dropped for format 12. Auth-only
            // mutations need not affect these two identity assertions.
            XCTAssertEqual(ordinal, expectedOrdinal)
            XCTAssertEqual(name, expectedName)
            // Can fail if auth bit 63 is ignored: metadata bit 32 produces addend 1.
            XCTAssertEqual(addend, 0)
            // Can fail if bind bit 62 is ignored. CANNOT-FAIL on auth-bit-only
            // loss: plain and authenticated binds intentionally both occupy.
            XCTAssertEqual(parsed.swiftSlotInventory.word(atSlot: input.fixture.chainedBindAddress),
                           .occupied(.bind), "format \(format)")
        }
    }

    func testGeneric64AuthenticatedLookingBytesRemainAnOrdinaryBind() throws {
        // In format 2, bit 63 means bind, not auth; bit 24 is unsigned addend 1.
        // The terminal word has next zero and ordinal zero.
        let raw = authBit | (UInt64(1) << 24)
        let fixture = MachOFixture.makeExecutableWithChainedFixupChain(
            imageBase: imageBase, pointerFormat: 2, rebaseRawOverride: raw
        )
        try assertInjected(raw, at: fixture.chainedRebaseAddress, in: fixture.bytes)
        let parsed = try MachOParser().parse(fixture.bytes)
        let chained = try XCTUnwrap(parsed.dyldChainedFixups)
        // Structural: can fail on next/stride loss, not an addend-only mutation.
        XCTAssertEqual(chained.fixups.count, 2)
        let terminal = try XCTUnwrap(chained.fixups.first { $0.address == fixture.chainedRebaseAddress })
        XCTAssertEqual(terminal.pointerFormat, 2)
        // Can fail if bit 63 is incorrectly interpreted as arm64e auth instead
        // of generic bind (or cleared): this word would become a rebase.
        guard case .bind(let ordinal, let name, let addend) = terminal.kind else {
            XCTFail("generic bit 63 was not decoded as a bind")
            return
        }
        // Identity assertions are CANNOT-FAIL for an auth/addend-only mutation.
        XCTAssertEqual(ordinal, 0)
        XCTAssertEqual(name, "_puts")
        // Can fail if bit 63 incorrectly suppresses an ordinary generic addend.
        XCTAssertEqual(addend, 1)
        // Can fail on misclassification as a rebase; not on addend-only loss.
        XCTAssertEqual(parsed.swiftSlotInventory.word(atSlot: fixture.chainedRebaseAddress), .occupied(.bind))
    }
}
