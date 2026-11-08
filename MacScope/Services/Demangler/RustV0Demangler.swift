/// Conservative display-only Rust v0 path subset. A successful display is not
/// evidence of language ownership, compiler version, ABI or source signature.
enum RustV0Demangler {
    private static let maximumInputBytes = 4096

    static func demangle(_ symbol: String) -> String? {
        // Do not materialize or count an unbounded UTF8 view first.
        var bytes: [UInt8] = []
        for byte in symbol.utf8 {
            guard bytes.count < maximumInputBytes else { return nil }
            bytes.append(byte)
        }
        var parser = Parser(bytes: bytes)
        return parser.parse()
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        var numericWork = 0
        var totalComponents = 0
        var output: [UInt8] = []
        static let maximumComponents = 64
        static let maximumOutputBytes = 2048
        static let maximumNumericWork = 256

        mutating func parse() -> String? {
            // Only the ordinary prefix or exactly one extra Mach-O underscore.
            guard take(95) else { return nil }
            if peek == 95 { index += 1 }
            guard take(82) else { return nil }
            let generic = take(73)
            guard path() else { return nil }
            if generic {
                guard append("::<") else { return nil }
                var arguments = 0
                while peek != 69 {
                    guard arguments < 16, let tag = peek else { return nil }
                    if arguments != 0, !append(", ") { return nil }
                    if let basic = Self.basicType(tag) {
                        index += 1
                        guard append(basic) else { return nil }
                    } else {
                        guard path() else { return nil }
                    }
                    arguments += 1
                }
                guard arguments > 0, take(69), append(">") else { return nil }
            }
            guard index == bytes.count else { return nil }
            return String(decoding: output, as: UTF8.self)
        }

        // Each path consumes only C/N(t,v), never a generic or recursive type.
        // The counter belongs to the whole symbol, not to an individual argument.
        mutating func path() -> Bool {
            guard totalComponents < Self.maximumComponents else { return false }
            totalComponents += 1
            var components = 1
            // This subset's path is a linear chain. Avoid recursive stack growth.
            while take(78) {
                guard totalComponents < Self.maximumComponents,
                      peek == 116 || peek == 118 else { return false }
                index += 1
                components += 1
                totalComponents += 1
            }
            guard take(67) else { return false }
            for component in 0..<components {
                guard identifier(separated: component != 0) else { return false }
            }
            return true
        }

        // Only bounded static punctuation and primitive names reach this helper.
        mutating func append(_ text: StaticString) -> Bool {
            let count = text.utf8CodeUnitCount
            guard count <= Self.maximumOutputBytes - output.count else { return false }
            text.withUTF8Buffer { output.append(contentsOf: $0) }
            return true
        }

        static func basicType(_ tag: UInt8) -> StaticString? {
            switch tag {
            case 97: return "i8"
            case 98: return "bool"
            case 99: return "char"
            case 100: return "f64"
            case 101: return "str"
            case 102: return "f32"
            case 104: return "u8"
            case 105: return "isize"
            case 106: return "usize"
            case 108: return "i32"
            case 109: return "u32"
            case 110: return "i128"
            case 111: return "u128"
            case 115: return "i16"
            case 116: return "u16"
            case 117: return "()"
            case 120: return "i64"
            case 121: return "u64"
            default: return nil
            }
        }

        var peek: UInt8? { index < bytes.count ? bytes[index] : nil }

        mutating func take(_ byte: UInt8) -> Bool {
            guard peek == byte else { return false }
            index += 1
            return true
        }

        mutating func chargeNumber() -> Bool {
            guard numericWork < Self.maximumNumericWork else { return false }
            numericWork += 1
            return true
        }

        mutating func disambiguator() -> Bool {
            guard take(115) else { return true }
            var value: UInt64 = 0
            var digits = 0
            while let byte = peek, byte != 95 {
                guard digits < 11, chargeNumber(),
                      let digit = Self.base62(byte) else { return false }
                let product = value.multipliedReportingOverflow(by: 62)
                let sum = product.partialValue.addingReportingOverflow(digit)
                guard !product.overflow, !sum.overflow else { return false }
                value = sum.partialValue
                digits += 1
                index += 1
            }
            guard take(95) else { return false }
            // Empty base62 is zero; nonempty digits encode value + 1.
            if digits != 0 {
                let increment = value.addingReportingOverflow(1)
                guard !increment.overflow else { return false }
                value = increment.partialValue
            }
            // The disambiguator itself adds one more, even though not displayed.
            return !value.addingReportingOverflow(1).overflow
        }

        mutating func decimalLength() -> UInt64? {
            guard let first = peek, Self.isDigit(first), chargeNumber() else { return nil }
            index += 1
            if first == 48 { return 0 } // Zero consumes exactly one byte.
            var value = UInt64(first - 48)
            var digits = 1
            while let byte = peek, Self.isDigit(byte) {
                guard digits < 20, chargeNumber() else { return nil }
                let product = value.multipliedReportingOverflow(by: 10)
                let sum = product.partialValue.addingReportingOverflow(UInt64(byte - 48))
                guard !product.overflow, !sum.overflow else { return nil }
                value = sum.partialValue
                index += 1
                digits += 1
            }
            return value
        }

        mutating func identifier(separated: Bool) -> Bool {
            guard disambiguator(), let length = decimalLength(), length > 0 else { return false }
            let hasSeparator = take(95)
            guard let first = peek,
                  hasSeparator || (!Self.isDigit(first) && first != 95),
                  length <= UInt64(bytes.count - index) else { return false }
            let separatorBytes = separated ? 2 : 0
            guard output.count <= Self.maximumOutputBytes - separatorBytes,
                  length <= UInt64(Self.maximumOutputBytes - output.count - separatorBytes) else { return false }
            // Conversion and addition are safe only after the bounded remaining-span proof.
            let end = index + Int(length)
            for position in index..<end {
                let byte = bytes[position]
                guard Self.base62(byte) != nil || byte == 95 else { return false }
            }
            if separated { output.append(contentsOf: [58, 58]) }
            output.append(contentsOf: bytes[index..<end])
            index = end
            return true
        }

        static func isDigit(_ byte: UInt8) -> Bool { byte >= 48 && byte <= 57 }

        static func base62(_ byte: UInt8) -> UInt64? {
            switch byte {
            case 48...57: return UInt64(byte - 48)
            case 97...122: return UInt64(byte - 97 + 10)
            case 65...90: return UInt64(byte - 65 + 36)
            default: return nil
            }
        }
    }
}
