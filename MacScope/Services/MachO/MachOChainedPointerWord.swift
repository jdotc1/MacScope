/// Item 1270: a total, inert decoder of one chained-pointer word.
/// Frozen expression provenance: MachOParser.swift at
/// 83f80d9ba6dbd24dfda92e7830169f5ab86e4783. The parser references in the
/// comments below are historical expressions of that file; the current
/// constructs that hold them are named in each comment (the historical helpers
/// are retained in MachOChainedPointerWordTests as LegacyReference).
/// This preserves that parser, not an independently verified dyld specification.
struct MachOChainedPointerWord: Sendable, Equatable {
    let raw: UInt64
    let format: UInt16

    enum State: Sendable, Equatable {
        case unsupported(format: UInt16)
        case decoded(Fields)
    }

    /// Raw field views, including ordinal/addend on a rebase word. As in the
    /// legacy helpers, the caller decides whether that view is applicable.
    struct Fields: Sendable, Equatable {
        let isArm64e: Bool
        let isAuthenticated: Bool
        let isBind: Bool
        let next: Int
        let stride: Int
        let bindOrdinal: Int
        let inlineBindAddend: Int64
    }

    init(raw: UInt64, format: UInt16) {
        self.raw = raw
        self.format = format
    }

    // Historical expression of supportedPointerFormat and pointerFormatIsArm64e in
    // MachOParser.swift (both still present there as format-only queries); chained
    // pointer constants live in MachOConstants.swift.
    var state: State {
        let arm: Bool
        switch format {
        case MachOConstants.dyldChainedPtrArm64e,
             MachOConstants.dyldChainedPtrArm64eUserland,
             MachOConstants.dyldChainedPtrArm64eUserland24:
            arm = true
        case MachOConstants.dyldChainedPtr64, MachOConstants.dyldChainedPtr64Offset:
            arm = false
        default:
            return .unsupported(format: format)
        }

        // Historical expression of the walkChain field interpretation in MachOParser.swift,
        // whose current field owner is this type's state: arm64e auth63/bind62/next[51,61];
        // generic64 has no auth field, bind63/next[51,62]. Ordinal is low16
        // for formats1/9 and low24 for formats2/6/12, irrespective of auth.
        let auth = arm && (raw >> 63) & 0x1 == 1
        let bind = arm ? ((raw >> 62) & 0x1 == 1) : ((raw >> 63) & 0x1 == 1)
        let next = arm ? Int((raw >> 51) & 0x7ff) : Int((raw >> 51) & 0xfff)
        let mask: UInt64 = arm && format != MachOConstants.dyldChainedPtrArm64eUserland24
            ? 0xffff : 0xff_ffff

        // Historical expression: LegacyReference.chainedBindInlineAddend in the word test file;
        // the current inline addend interpretation is this state. Generic addend[24,31] is UNSIGNED.
        // Plain arm64e addend[32,50] is signed19; authenticated addend is0.
        let addend: Int64
        if !arm {
            addend = Int64((raw >> 24) & 0xff)
        } else if auth {
            addend = 0
        } else {
            let addend19 = (raw >> 32) & 0x7_ffff
            addend = addend19 & 0x4_0000 != 0
                ? Int64(bitPattern: addend19 | 0xffff_ffff_fff8_0000)
                : Int64(addend19)
        }
        return .decoded(Fields(isArm64e: arm, isAuthenticated: auth, isBind: bind,
                               next: next, stride: arm ? 8 : 4,
                               bindOrdinal: Int(raw & mask), inlineBindAddend: addend))
        // Stride8/4 is lifted from pointerStride(for:) in MachOParser.swift.
    }

    var fields: Fields? {
        guard case .decoded(let value) = state else { return nil }
        return value
    }

    /// Same raw-word interpretation as the historical LegacyReference.rebaseTargetAddress
    /// (word test file), even if the
    /// caller supplies a bind word. Unsupported formats never reach its legacy
    /// default branch: they explicitly have no target. No authentication occurs.
    func rebaseTargetAddress(imageBase: UInt64) -> UInt64? {
        guard case .decoded = state else { return nil }
        switch format {
        case MachOConstants.dyldChainedPtr64:
            // Generic absolute branch: low36 target, high8[36,43], absolute unslid VA.
            let target = raw & 0xf_ffff_ffff
            let high8 = (raw >> 36) & 0xff
            return target | (high8 << 56)
        case MachOConstants.dyldChainedPtr64Offset:
            // Generic offset branch: base + low36, then ADD high8 into top byte.
            let (target, overflow) = imageBase.addingReportingOverflow(raw & 0xf_ffff_ffff)
            guard !overflow else { return nil }
            return Self.addingHigh8(target, high8: (raw >> 36) & 0xff)
        case MachOConstants.dyldChainedPtrArm64e where (raw >> 63) & 1 == 0:
            // Plain arm64e branch: plain format1 low43/high8[43,50], absolute VA.
            let target = raw & 0x7ff_ffff_ffff
            let high8 = (raw >> 43) & 0xff
            return target | (high8 << 56)
        default:
            // Remaining arm64e branches: auth arm64e uses base + low32 and ignores high8;
            // plain USERLAND/USERLAND24 uses base + low43, then adds high8.
            let isAuth = (raw >> 63) & 0x1 == 1
            let offset = isAuth ? (raw & 0xffff_ffff) : (raw & 0x7ff_ffff_ffff)
            let (target, overflow) = imageBase.addingReportingOverflow(offset)
            guard !overflow else { return nil }
            return isAuth ? target : Self.addingHigh8(target, high8: (raw >> 43) & 0xff)
        }
    }

    // Historical LegacyReference.addingHigh8 (word test file). All callers mask high8 to eight bits.
    private static func addingHigh8(_ target: UInt64, high8: UInt64) -> UInt64? {
        let (result, overflow) = target.addingReportingOverflow(high8 << 56)
        return overflow ? nil : result
    }
}
