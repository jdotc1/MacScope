import Foundation

enum NativeFunctionContractError: Error, Equatable {
    case unsupportedScalarInput
    case invalidInteger
    case integerOutOfRange
    case invalidPrototype
    case invalidValueWidth
}

/// Closed vocabulary for the first native-call ABI. No declaration text is executable input.
enum NativeFunctionScalarType: String, CaseIterable, Codable, Sendable {
    case void, int8, uint8, int16, uint16, int32, uint32, int64, uint64, pointer

    var byteCount: Int {
        switch self {
        case .void: 0
        case .int8, .uint8: 1
        case .int16, .uint16: 2
        case .int32, .uint32: 4
        case .int64, .uint64, .pointer: 8
        }
    }

    var isSigned: Bool { [.int8, .int16, .int32, .int64].contains(self) }

    var cDeclaration: String {
        switch self {
        case .void: "void"
        case .int8: "signed char"
        case .uint8: "unsigned char"
        case .int16: "short"
        case .uint16: "unsigned short"
        case .int32: "int"
        case .uint32: "unsigned int"
        case .int64: "long long"
        case .uint64: "unsigned long long"
        case .pointer: "void *"
        }
    }

    /// Decimal uses the declared signed range; hexadecimal supplies exact raw bits.
    /// Pointer addresses are never accepted through this scalar-input interface.
    func parseInteger(_ input: String) throws -> Data {
        guard self != .void, self != .pointer else {
            throw NativeFunctionContractError.unsupportedScalarInput
        }
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.count <= 128 else {
            throw NativeFunctionContractError.invalidInteger
        }
        let bits = byteCount * 8
        let mask: UInt64 = bits == 64 ? .max : (UInt64(1) << bits) - 1
        let raw: UInt64
        if text.hasPrefix("0x") || text.hasPrefix("0X") {
            let digits = text.dropFirst(2)
            guard !digits.isEmpty,
                  digits.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
                  let value = UInt64(digits, radix: 16) else {
                throw NativeFunctionContractError.invalidInteger
            }
            guard value <= mask else { throw NativeFunctionContractError.integerOutOfRange }
            raw = value
        } else if isSigned {
            let digits = text.hasPrefix("-") || text.hasPrefix("+") ? text.dropFirst() : text[...]
            guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }),
                  let value = Int64(text) else { throw NativeFunctionContractError.invalidInteger }
            if bits < 64 {
                let maximum = (Int64(1) << (bits - 1)) - 1
                guard value >= -maximum - 1, value <= maximum else {
                    throw NativeFunctionContractError.integerOutOfRange
                }
            }
            raw = UInt64(bitPattern: value) & mask
        } else {
            guard text.utf8.allSatisfy({ (48...57).contains($0) }),
                  let value = UInt64(text) else { throw NativeFunctionContractError.invalidInteger }
            guard value <= mask else { throw NativeFunctionContractError.integerOutOfRange }
            raw = value
        }
        return Data((0..<byteCount).map { UInt8(truncatingIfNeeded: raw >> ($0 * 8)) })
    }
}

struct NativeFunctionPrototype: Equatable, Sendable {
    enum Provenance: String, Sendable { case authoritativeDWARF, userOverride }
    let returnType: NativeFunctionScalarType
    let parameterTypes: [NativeFunctionScalarType]
    let provenance: Provenance

    init(returnType: NativeFunctionScalarType, parameterTypes: [NativeFunctionScalarType],
         provenance: Provenance) throws {
        guard parameterTypes.count <= 16, !parameterTypes.contains(.void) else {
            throw NativeFunctionContractError.invalidPrototype
        }
        self.returnType = returnType
        self.parameterTypes = parameterTypes
        self.provenance = provenance
    }

    var functionPointerDeclaration: String {
        let parameters = parameterTypes.isEmpty ? "void" : parameterTypes.map(\.cDeclaration).joined(separator: ", ")
        return "\(returnType.cDeclaration) (*)(\(parameters))"
    }
}

struct NativeFunctionTypedValue: Equatable, Sendable {
    let type: NativeFunctionScalarType
    let bytes: Data

    init(type: NativeFunctionScalarType, bytes: Data) throws {
        guard bytes.count == type.byteCount else { throw NativeFunctionContractError.invalidValueWidth }
        self.type = type
        self.bytes = bytes
    }

    var rawBits: UInt64 {
        bytes.enumerated().reduce(0) { $0 | UInt64($1.element) << ($1.offset * 8) }
    }

    var hexadecimal: String {
        "0x" + bytes.reversed().map { String(format: "%02x", $0) }.joined()
    }

    var decimal: String? {
        guard type != .void, type != .pointer else { return nil }
        let bits = rawBits
        guard type.isSigned else { return String(bits) }
        let width = type.byteCount * 8
        let extended = width < 64 && (bits & (UInt64(1) << (width - 1))) != 0
            ? bits | (.max << width) : bits
        return String(Int64(bitPattern: extended))
    }
}
