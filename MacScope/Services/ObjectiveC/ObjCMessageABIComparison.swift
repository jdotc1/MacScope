import Foundation

// Reference seam: these shapes MUST come from the qualified DWARF catalog/layout
// binder, not from parsing the display spelling. Typedefs and const are resolved
// upstream; fixed enums resolve to scalar, lossy/unknown-fixedness enums retain
// their marker. Neither a caller assertion nor a runtime encoding supplies DWARF
// authority. This file does not implement snapshot policy (item 348).
enum ObjCMessageABIComparison {
    enum Shape: Hashable, Sendable {
        case s8, u8, s16, u16, s32, u32, s64, u64, bool, f32, f64
        case object, classPointer, selector, block, dataPointer, void
        case lossyEnum(Scalar), unknown
        enum Scalar: Hashable, Sendable { case s32, other }
        var pointer: Bool {
            switch self {
            case .object, .classPointer, .selector, .block, .dataPointer: return true
            default: return false
            }
        }
    }
    struct DebugType: Equatable, Sendable {
        let spelling: String
        let shape: Shape
    }
    struct DebugPrototype: Sendable {
        let returnType: DebugType
        /// Includes self and _cmd, in declaration order.
        let parameters: [DebugType]
    }
    enum Verdict: Equatable { case agree, contradiction, unclassified }

    // 343 comparison table: scalar rows 2–59, pointer rows 61–99,
    // enum rows 100–111, qualifiers 112–123, void rows 137–140.
    static func compare(runtime: Shape, debug: Shape, isReturn: Bool) -> Verdict {
        if runtime == .unknown || debug == .unknown { return .unclassified }
        if case .lossyEnum(let underlying) = debug {
            return runtime == .s32 && underlying == .s32 ? .agree : .unclassified
        }
        if !isReturn && (runtime == .void || debug == .void) { return .unclassified }
        if runtime == debug { return .agree }
        if runtime.pointer && debug.pointer { return .unclassified }
        return .contradiction
    }

    /// Strict whole-string, bounded grammar. Unsupported composites/wrappers are
    /// conservatively unclassified (including pointers to those constructs).
    /// No prefix success, padding absent arguments, or nil-as-agreement.
    static func decode(_ text: String, arity: Int) -> [Shape]? {
        guard arity >= 0, arity <= 64, !text.isEmpty, text.utf8.count <= 4096 else { return nil }
        let bytes = Array(text.utf8)
        var i = 0
        func digit(_ b: UInt8) -> Bool { b >= 48 && b <= 57 }
        func type(_ depth: Int) -> Shape? {
            guard depth < 16 else { return nil }
            while i < bytes.count && Array("rnNoORV".utf8).contains(bytes[i]) { i += 1 }
            guard i < bytes.count else { return nil }
            let code = bytes[i]; i += 1
            switch code {
            case 99: return .s8
            case 67: return .u8
            case 115: return .s16
            case 83: return .u16
            case 105, 108: return .s32
            case 73, 76: return .u32
            case 113: return .s64
            case 81: return .u64
            case 66: return .bool
            case 102: return .f32
            case 100, 68: return .f64
            case 118: return .void
            case 35: return .classPointer
            case 58: return .selector
            case 42: return .dataPointer
            case 64:
                if i < bytes.count && bytes[i] == 63 { i += 1; return .block }
                if i < bytes.count && bytes[i] == 34 {
                    i += 1
                    let start = i
                    while i < bytes.count && bytes[i] != 34 {
                        guard bytes[i] >= 32, bytes[i] != 92 else { return nil }
                        i += 1
                    }
                    guard i > start, i < bytes.count else { return nil }
                    i += 1
                }
                return .object
            case 94:
                guard let pointee = type(depth + 1), pointee != .unknown else { return nil }
                return .dataPointer
            default: return nil
            }
        }
        var result: [Shape] = []
        while i < bytes.count {
            guard result.count < arity + 3, let shape = type(0) else { return nil }
            result.append(shape)
            // Offsets are optional decimal numbers, with optional minus sign.
            if i < bytes.count && bytes[i] == 45 {
                i += 1
                guard i < bytes.count && digit(bytes[i]) else { return nil }
            }
            while i < bytes.count && digit(bytes[i]) { i += 1 }
        }
        guard result.count == arity + 3,
              result[1] == .object || result[1] == .classPointer,
              result[2] == .selector else { return nil }
        return result
    }
}
