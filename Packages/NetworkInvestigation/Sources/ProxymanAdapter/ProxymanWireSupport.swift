import Foundation
import CryptoKit
import ExternalMCP
import NetworkEvidenceCore

extension ProxymanMinimizer {
    static func identifier(_ value: MCPJSONValue?) -> String? {
        let text: String
        switch value {
        case .string(let v): text = v
        case .int(let v) where v >= 0: text = String(v)
        default: return nil
        }
        guard (1...128).contains(text.utf8.count), text.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }) else { return nil }
        return text
    }

    static func version(_ value: MCPJSONValue?) -> String? {
        let text: String
        switch value { case .string(let v): text = v; case .int(let v): text = String(v); default: return nil }
        guard (1...64).contains(text.utf8.count), text.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 43, 95].contains($0)
        }) else { return nil }
        return text
    }
}

enum ProxymanDigest {
    static func json(_ value: MCPJSONValue) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(value)
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}

extension MCPJSONValue {
    var pObject: [String: MCPJSONValue]? { if case .object(let value) = self { value } else { nil } }
    var pArray: [MCPJSONValue]? { if case .array(let value) = self { value } else { nil } }
    var pString: String? { if case .string(let value) = self { value } else { nil } }
    var pBool: Bool? { if case .bool(let value) = self { value } else { nil } }
    var pNumber: Double? {
        switch self { case .int(let v): Double(v); case .double(let v) where v.isFinite: v; default: nil }
    }
    var pInt: Int? {
        switch self {
        case .int(let v): v
        case .double(let v) where v.isFinite && v.rounded() == v: Int(exactly: v)
        default: nil
        }
    }
}

extension Dictionary where Key == String, Value == MCPJSONValue {
    func first(_ names: [String]) -> MCPJSONValue? {
        for name in names { if let value = self[name], value != .null { return value } }
        return nil
    }
}
