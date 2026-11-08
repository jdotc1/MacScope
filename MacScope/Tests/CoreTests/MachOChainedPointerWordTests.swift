import XCTest
@testable import MacScope

/// Authored-unrun. Frozen reference expressions come from the supplied parser,
/// not MachOChainedPointerWord. This is extraction parity, not dyld conformance.
final class MachOChainedPointerWordTests: XCTestCase {
    private let formats: [UInt16] = [1, 2, 6, 9, 12]
    private let bases: [UInt64] = [0, 0x1_0000_0000, 0x0100_0000_0000_0000,
                                  0xffff_fff0_0000_0000, UInt64.max]

    func testBoundaryWordsMatchFrozenLegacyReference() throws {
        for format in formats {
            let arm = LegacyReference.pointerFormatIsArm64e(format)
            let ordinalMax: UInt64 = arm && format != 12 ? 0xffff : 0xff_ffff
            let bind: UInt64 = UInt64(1) << (arm ? 62 : 63)
            let maxNext: UInt64 = arm ? 0x7ff : 0xfff
            // Explicitly retain named duplicates: auth-only == single-bit63,
            // and generic bind-only == auth-looking-only.
            var words: [UInt64] = [
                0, UInt64.max, UInt64(1) << 63, bind, (UInt64(1) << 63) | bind,
                maxNext << 51, ordinalMax, ordinalMax + 1,
                bind | ordinalMax, bind | (ordinalMax + 1),
                UInt64(1) << 50, bind | (UInt64(0x4_0000) << 32),
                bind | (UInt64(0x3_ffff) << 32), bind | (UInt64(0x7_ffff) << 32),
                UInt64(0xff) << 24,
                (UInt64(0xff) << 36) | 0xf_ffff_ffff,
                (UInt64(0xff) << 43) | 0x7ff_ffff_ffff,
                (UInt64(1) << 63) | 0xffff_ffff,
            ]
            words += (0..<64).map { UInt64(1) << $0 }
            for raw in words { try assertParity(raw: raw, format: format) }
        }
    }

    func testFixedSeedWordsMatchFrozenLegacyReference() throws {
        // Exactly 256 words PER FORMAT, reset seed for the same cross-product.
        // Wrapping LCG arithmetic is deliberate; no RNG, corpus or I/O.
        for format in formats {
            var state: UInt64 = 0x1270_2026_1106_0001
            for _ in 0..<256 {
                state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                try assertParity(raw: state, format: format)
            }
        }
    }

    func testUnsupportedFormatsHaveAnExplicitStateAndNoFieldsOrTarget() {
        for format: UInt16 in [0, 3, 4, 5, 7, 8, 10, 11, 13, UInt16.max] {
            XCTAssertFalse(LegacyReference.supportedPointerFormat(format))
            for raw: UInt64 in [0, UInt64.max, UInt64(1) << 63] {
                let word = MachOChainedPointerWord(raw: raw, format: format)
                XCTAssertEqual(word.state, .unsupported(format: format))
                XCTAssertNil(word.fields)
                for base in bases { XCTAssertNil(word.rebaseTargetAddress(imageBase: base)) }
                XCTAssertEqual(word.raw, raw)
                XCTAssertEqual(word.format, format)
                XCTAssertEqual(word, MachOChainedPointerWord(raw: raw, format: format))
            }
        }
    }

    func testOrdinalWidthsAgreeWithFrozenAuditReservedBitGate() throws {
        // Audit policy is deliberately NOT delegated. Pin the distinction
        // between truncating a raw ordinal and refusing its reserved high bits.
        for format in formats {
            let arm = LegacyReference.pointerFormatIsArm64e(format)
            let width = arm && format != 12 ? 16 : 24
            let mask = (UInt64(1) << width) - 1
            let bind = UInt64(1) << (arm ? 62 : 63)
            let maximum = try XCTUnwrap(MachOChainedPointerWord(raw: bind | mask, format: format).fields)
            XCTAssertEqual(maximum.bindOrdinal, Int(mask))
            XCTAssertTrue(LegacyReference.auditBindReservedBitsAreZero(raw: bind | mask, format: format))
            let above = bind | (UInt64(1) << width)
            let truncated = try XCTUnwrap(MachOChainedPointerWord(raw: above, format: format).fields)
            XCTAssertEqual(truncated.bindOrdinal, 0)
            // Generic bit24 is addend, not a reserved ordinal bit; arm64e
            // reserves bits[width,31]. Generic reserved bits start at32.
            XCTAssertEqual(LegacyReference.auditBindReservedBitsAreZero(raw: above, format: format), !arm)
            XCTAssertFalse(LegacyReference.auditBindReservedBitsAreZero(
                raw: bind | (UInt64(1) << (arm ? width : 32)), format: format))
        }
        for format: UInt16 in [1, 9, 12] {
            let raw = (UInt64(1) << 63) | (UInt64(1) << 62) | (UInt64(1) << 16)
            let fields = try XCTUnwrap(MachOChainedPointerWord(raw: raw, format: format).fields)
            XCTAssertEqual(fields.bindOrdinal, format == 12 ? 65_536 : 0)
            XCTAssertEqual(LegacyReference.auditBindReservedBitsAreZero(raw: raw, format: format), format == 12)
        }
    }

    private func assertParity(raw: UInt64, format: UInt16,
                              file: StaticString = #filePath, line: UInt = #line) throws {
        let word = MachOChainedPointerWord(raw: raw, format: format)
        let actual = try XCTUnwrap(word.fields, file: file, line: line)
        let expected = LegacyReference.fields(raw: raw, pointerFormat: format)
        let label = "format=\(format) raw=\(raw)"
        XCTAssertTrue(LegacyReference.supportedPointerFormat(format), label, file: file, line: line)
        XCTAssertEqual(word.raw, raw, label, file: file, line: line)
        XCTAssertEqual(word.format, format, label, file: file, line: line)
        XCTAssertEqual(actual.isArm64e, expected.arm, label, file: file, line: line)
        XCTAssertEqual(actual.isAuthenticated, expected.auth, label, file: file, line: line)
        XCTAssertEqual(actual.isBind, expected.bind, label, file: file, line: line)
        XCTAssertEqual(actual.next, expected.next, label, file: file, line: line)
        XCTAssertEqual(actual.bindOrdinal, expected.ordinal, label, file: file, line: line)
        XCTAssertEqual(actual.stride, LegacyReference.pointerStride(for: format), label, file: file, line: line)
        XCTAssertEqual(actual.inlineBindAddend,
                       LegacyReference.chainedBindInlineAddend(raw: raw, pointerFormat: format),
                       label, file: file, line: line)
        for base in bases {
            XCTAssertEqual(word.rebaseTargetAddress(imageBase: base),
                           LegacyReference.rebaseTargetAddress(raw: raw, pointerFormat: format, imageBase: base),
                           "\(label) base=\(base)", file: file, line: line)
        }
        XCTAssertEqual(word.state, .decoded(actual), label, file: file, line: line)
        XCTAssertEqual(word, MachOChainedPointerWord(raw: raw, format: format), file: file, line: line)
    }

    private enum LegacyReference {
        // FROZEN predicates from MachOParser.swift:4440-4444 (part7).
        // Only the guard/throw control flow is replaced by a returned Bool.
        static func auditBindReservedBitsAreZero(raw: UInt64, format: UInt16) -> Bool {
            if pointerFormatIsArm64e(format) {
                let ordinalBits = format == MachOConstants.dyldChainedPtrArm64eUserland24 ? 24 : 16
                return (raw >> ordinalBits) & ((UInt64(1) << (32 - ordinalBits)) - 1) == 0
            } else {
                return (raw >> 32) & 0x7ffff == 0
            }
        }

        // FROZEN COPY from MachOParser.swift:1697-1699,1706-1708 (part3).
        // Only test wrapper/tuple return added. Auth expression is copied from
        // :1815 and applied only to arm64e (generic formats have no auth field).
        static func fields(raw: UInt64, pointerFormat: UInt16)
            -> (arm: Bool, auth: Bool, bind: Bool, next: Int, ordinal: Int) {
            let isArm64e = pointerFormatIsArm64e(pointerFormat)
            let isBind = isArm64e ? ((raw >> 62) & 0x1 == 1) : ((raw >> 63) & 0x1 == 1)
            let next = isArm64e ? Int((raw >> 51) & 0x7ff) : Int((raw >> 51) & 0xfff)
            let ordinalMask: UInt64 = isArm64e && pointerFormat != MachOConstants.dyldChainedPtrArm64eUserland24
                ? 0xffff : 0xff_ffff
            let ordinalBits = Int(raw & ordinalMask)
            let isAuth = (raw >> 63) & 0x1 == 1
            return (isArm64e, isArm64e && isAuth, isBind, next, ordinalBits)
        }

        // FROZEN COPY: MachOParser.swift:1404-1419 (part3); body unchanged.
        static func chainedBindInlineAddend(raw: UInt64, pointerFormat: UInt16) -> Int64 {
            switch pointerFormat {
            case MachOConstants.dyldChainedPtr64, MachOConstants.dyldChainedPtr64Offset:
                return Int64((raw >> 24) & 0xff)
            case MachOConstants.dyldChainedPtrArm64e,
                MachOConstants.dyldChainedPtrArm64eUserland,
                MachOConstants.dyldChainedPtrArm64eUserland24:
                guard (raw >> 63) & 0x1 == 0 else { return 0 }
                let addend19 = (raw >> 32) & 0x7_ffff
                return addend19 & 0x4_0000 != 0
                    ? Int64(bitPattern: addend19 | 0xffff_ffff_fff8_0000)
                    : Int64(addend19)
            default:
                return 0
            }
        }

        // FROZEN COPY: MachOParser.swift:1794-1821 (part3); body unchanged.
        static func rebaseTargetAddress(raw: UInt64, pointerFormat: UInt16, imageBase: UInt64) -> UInt64? {
            switch pointerFormat {
            case MachOConstants.dyldChainedPtr64:
                // dyld_chained_ptr_64_rebase: target:36, high8:8 — an absolute unslid VM address.
                let target = raw & 0xf_ffff_ffff
                let high8 = (raw >> 36) & 0xff
                return target | (high8 << 56)
            case MachOConstants.dyldChainedPtr64Offset:
                // _64_OFFSET stores a runtime offset from the image base; dyld adds the base to
                // the unpacked target, which keeps high8 in the top byte.
                let (target, overflow) = imageBase.addingReportingOverflow(raw & 0xf_ffff_ffff)
                guard !overflow else { return nil }
                return Self.addingHigh8(target, high8: (raw >> 36) & 0xff)
            case MachOConstants.dyldChainedPtrArm64e where (raw >> 63) & 1 == 0:
                // Plain ARM64E (format 1) stores an unslid address, unlike USERLAND.
                let target = raw & 0x7ff_ffff_ffff
                let high8 = (raw >> 43) & 0xff
                return target | (high8 << 56)
            default:
                // Authenticated ARM64E rebases and USERLAND plain rebases use offsets. Only the
                // plain rebase carries high8 (bits 43..50); the auth rebase target is 32 bits.
                let isAuth = (raw >> 63) & 0x1 == 1
                let offset = isAuth ? (raw & 0xffff_ffff) : (raw & 0x7ff_ffff_ffff)
                let (target, overflow) = imageBase.addingReportingOverflow(offset)
                guard !overflow else { return nil }
                return isAuth ? target : Self.addingHigh8(target, high8: (raw >> 43) & 0xff)
            }
        }

        // FROZEN COPY: MachOParser.swift:1824-1827 (part3); body unchanged.
        private static func addingHigh8(_ target: UInt64, high8: UInt64) -> UInt64? {
            let (result, overflow) = target.addingReportingOverflow(high8 << 56)
            return overflow ? nil : result
        }

        // FROZEN COPY: MachOParser.swift:1829-1840 (part3); body unchanged.
        static func supportedPointerFormat(_ format: UInt16) -> Bool {
            switch format {
            case MachOConstants.dyldChainedPtr64,
                MachOConstants.dyldChainedPtr64Offset,
                MachOConstants.dyldChainedPtrArm64e,
                MachOConstants.dyldChainedPtrArm64eUserland,
                MachOConstants.dyldChainedPtrArm64eUserland24:
                return true
            default:
                return false
            }
        }

        // FROZEN COPY: MachOParser.swift:1842-1851 (part3); body unchanged.
        static func pointerFormatIsArm64e(_ format: UInt16) -> Bool {
            switch format {
            case MachOConstants.dyldChainedPtrArm64e,
                MachOConstants.dyldChainedPtrArm64eUserland,
                MachOConstants.dyldChainedPtrArm64eUserland24:
                return true
            default:
                return false
            }
        }

        // FROZEN COPY: MachOParser.swift:1855-1857 (part3); body unchanged.
        static func pointerStride(for format: UInt16) -> Int {
            pointerFormatIsArm64e(format) ? 8 : 4
        }
    }
}
