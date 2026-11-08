import Foundation

/// Bridges Cocoa scripting values — the `[String: Any]` an `NSScriptCommand` exposes via
/// `evaluatedArguments`, built from NSNumber / NSString / NSArray / NSDictionary — to and
/// from the in-process `ScriptValue` model. Kept pure so the conversion is unit-testable
/// without a running app or a live Apple event; the `NSScriptCommand` shell is the only
/// piece that needs the real dispatcher.
enum AppleScriptArgumentBridge {

    /// Converts one Cocoa scripting value into a `ScriptValue`. Unrecognized values (and
    /// `NSNull`) become `.null` rather than trapping — a malformed Apple event can never
    /// take down the process.
    static func scriptValue(from any: Any) -> ScriptValue {
        switch any {
        case let record as MacScopeScriptRecord:
            return record.value
        case let value as ScriptValue:
            return value
        case is NSNull:
            return .null
        case let number as NSNumber:
            // CFBoolean is an NSNumber; distinguish it so true/false round-trip as bool.
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return .bool(number.boolValue)
            }
            // Integral numbers map to .int; only genuinely fractional ones to .double.
            let double = number.doubleValue
            if double.rounded(.towardZero) == double, let int = Int64(exactly: double) {
                return .int(int)
            }
            return .double(double)
        case let string as String:
            return .string(string)
        case let dictionary as [String: Any]:
            return .object(dictionary.mapValues(scriptValue(from:)))
        case let array as [Any]:
            return .array(array.map(scriptValue(from:)))
        default:
            return .null
        }
    }

    /// Converts a record of Cocoa scripting arguments to `ScriptValue` parameters.
    static func scriptValues(from arguments: [String: Any]) -> [String: ScriptValue] {
        arguments.mapValues(scriptValue(from:))
    }

    /// The generic verb declares a text result in MacScope.sdef; all other verbs
    /// retain their typed Cocoa results. Serialize before AppKit constructs the reply.
    static func cocoaReply(from value: ScriptValue, command: String) throws -> Any {
        if command == "run command" {
            // Validate typed output before any recursive Foundation bridge.
            let data: Data
            do { data = try value.jsonData() }
            catch {
                throw NSError(domain: "MacScope.Scripting", code: -1750,
                    userInfo: [NSLocalizedDescriptionKey: "Scripting reply contains a value that cannot be encoded as JSON."])
            }
            return String(decoding: data, as: UTF8.self)
        }
        return cocoaValue(from: value)
    }

    /// Converts a `ScriptValue` result back to a Cocoa value an `NSScriptCommand` can return
    /// (NSString / NSNumber / NSArray / NSDictionary / NSNull), preserving structure.
    static func cocoaValue(from value: ScriptValue) -> Any {
        switch value {
        case .null: return NSNull()
        case let .bool(bool): return bool
        case let .int(int): return Int(int)
        case let .double(double): return double
        case let .string(string): return string
        case let .array(items): return items.map(cocoaValue(from:))
        case let .object(fields): return fields.mapValues(cocoaValue(from:))
        }
    }
}

/// Cocoa invokes this value-type converter before constructing NSScriptCommand.
/// A standard property record cannot represent arbitrary user-supplied field names.
@objc(MacScopeScriptRecord)
final class MacScopeScriptRecord: NSObject {
    let value: ScriptValue

    private init(value: ScriptValue) { self.value = value }

    @objc(scriptingUserDefinedRecordWithDescriptor:)
    class func scriptingUserDefinedRecord(with descriptor: NSAppleEventDescriptor) -> MacScopeScriptRecord? {
        var remaining = 10_000
        guard descriptor.descriptorType == 0x7265636f, // reco
              let value = decode(descriptor, depth: 0, remaining: &remaining) else { return nil }
        return MacScopeScriptRecord(value: value)
    }

    private static func decode(_ descriptor: NSAppleEventDescriptor, depth: Int,
                               remaining: inout Int) -> ScriptValue? {
        guard depth < 32, remaining > 0 else { return nil }
        remaining -= 1
        switch descriptor.descriptorType {
        case 0x7265636f: // reco: fields are alternating names/values in the usrf list
            guard let fields = descriptor.forKeyword(0x75737266) else {
                return descriptor.numberOfItems == 0 ? .object([:]) : nil
            }
            guard descriptor.numberOfItems == 1, fields.descriptorType == 0x6c697374,
                  fields.numberOfItems % 2 == 0, fields.numberOfItems <= remaining * 2 else { return nil }
            var result: [String: ScriptValue] = [:]
            for index in stride(from: 1, through: fields.numberOfItems, by: 2) {
                guard let keyDescriptor = fields.atIndex(index),
                      [UInt32(0x75747874), 0x75746638, 0x54455854].contains(keyDescriptor.descriptorType),
                      let key = keyDescriptor.stringValue, result[key] == nil,
                      let item = fields.atIndex(index + 1),
                      let value = decode(item, depth: depth + 1, remaining: &remaining) else { return nil }
                result[key] = value
            }
            return .object(result)
        case 0x6c697374: // list
            guard descriptor.numberOfItems <= remaining else { return nil }
            var values: [ScriptValue] = []
            for index in 0..<descriptor.numberOfItems {
                guard let item = descriptor.atIndex(index + 1),
                      let value = decode(item, depth: depth + 1, remaining: &remaining) else { return nil }
                values.append(value)
            }
            return .array(values)
        case 0x75747874, 0x75746638, 0x54455854: // utxt, utf8, TEXT
            return descriptor.stringValue.map(ScriptValue.string)
        case 0x626f6f6c, 0x74727565, 0x66616c73: // bool, true, fals
            return .bool(descriptor.booleanValue)
        case 0x73686f72, 0x6c6f6e67: // shor, long
            return .int(Int64(descriptor.int32Value))
        case 0x636f6d70: // comp: preserve all signed 64-bit bits without Double conversion
            guard descriptor.data.count == MemoryLayout<Int64>.size else { return nil }
            return .int(descriptor.data.withUnsafeBytes { $0.loadUnaligned(as: Int64.self) })
        case 0x646f7562: // doub
            let number = descriptor.doubleValue
            return number.isFinite ? .double(number) : nil
        case 0x6e756c6c: // null
            return .null
        case 0x74797065 where descriptor.typeCodeValue == 0x6d736e67: // missing value
            return .null
        default:
            return nil
        }
    }
}
