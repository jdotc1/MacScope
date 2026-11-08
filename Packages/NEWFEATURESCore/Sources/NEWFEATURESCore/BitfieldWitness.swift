import Foundation

/// This module recognizes only already-extracted, side-effect-free unsigned bit
/// patterns. It does not attempt to rewrite arbitrary MacIR/SSA syntax.
public struct NEWFEATURESBitfieldLayout: Sendable, Equatable {
    public let memberName: String
    public let storageBits: Int
    public let offset: Int
    public let width: Int
    public let isSigned: Bool

    public init(
        memberName: String,
        storageBits: Int,
        offset: Int,
        width: Int,
        isSigned: Bool
    ) throws {
        guard !memberName.isEmpty, memberName.utf8.count <= 256,
              [8, 16, 32, 64].contains(storageBits), offset >= 0, width > 0,
              width <= storageBits, offset <= storageBits - width else {
            throw NEWFEATURESError.malformedFact("invalid bitfield layout")
        }
        self.memberName = memberName
        self.storageBits = storageBits
        self.offset = offset
        self.width = width
        self.isSigned = isSigned
    }

    public var extractionMask: UInt64 {
        width == 64 ? UInt64.max : ((UInt64(1) << width) - 1)
    }

    public var positionedMask: UInt64 { extractionMask << offset }
    public var storageMask: UInt64 {
        storageBits == 64 ? UInt64.max : (UInt64(1) << storageBits) - 1
    }
}

public struct NEWFEATURESBitfieldWitness: Sendable {
    public let memberName: String
    public let justification: String
    public let storageMask: UInt64
}

public enum NEWFEATURESBitfieldRecovery {
    /// Recognizes (pure_storage >> shift) & mask, only if exact layout agrees.
    public static func unsignedRead(
        layout: NEWFEATURESBitfieldLayout,
        shift: Int,
        mask: UInt64,
        hasSideEffects: Bool
    ) -> NEWFEATURESBitfieldWitness? {
        guard !layout.isSigned, !hasSideEffects,
              shift == layout.offset, mask == layout.extractionMask else { return nil }
        return NEWFEATURESBitfieldWitness(
            memberName: layout.memberName,
            justification: "typed-layout-exact-unsigned-read",
            storageMask: layout.positionedMask
        )
    }

    /// Recognizes (old & clearMask) | ((pure_new & valueMask) << shift).
    /// This is a candidate witness only; alias/volatile/concurrency checks must
    /// occur in the existing MacIR pass before an emitted member assignment.
    public static func unsignedWrite(
        layout: NEWFEATURESBitfieldLayout,
        clearMask: UInt64,
        valueMask: UInt64,
        shift: Int,
        hasSideEffects: Bool
    ) -> NEWFEATURESBitfieldWitness? {
        guard !layout.isSigned, !hasSideEffects,
              shift == layout.offset, valueMask == layout.extractionMask,
              clearMask == ((~layout.positionedMask) & layout.storageMask) else { return nil }
        return NEWFEATURESBitfieldWitness(
            memberName: layout.memberName,
            justification: "typed-layout-exact-unsigned-update",
            storageMask: layout.positionedMask
        )
    }
}
