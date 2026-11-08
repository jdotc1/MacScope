import Foundation

/// Public model selection shared by `unwind-audit` and `swift-error-flow`. The raw values are the wire names.
enum AIRSReadModel: String, CaseIterable, Sendable {
    case v1, v4, registerCopiesV2, regionsV1, outcomeWitnessV2

    var unwindModel: UnwindAuditModel? {
        switch self {
        case .v1: return .boundedLoops
        case .v4: return .boundedCFIControls
        default: return nil
        }
    }

    /// The raw analysis model identity of the command's own analyzer.
    func modelID(for command: String) -> String {
        if command == AIRSMCPReads.unwindCommand { return (unwindModel ?? .boundedLoops).rawValue }
        switch self {
        case .registerCopiesV2: return SwiftErrorFlowModel.registerCopiesV2.rawValue
        case .regionsV1: return "macscope-swift-error-region-native-v1"
        case .outcomeWitnessV2: return "macscope-swift-outcome-witness-v2"
        default: return SwiftErrorFlowModel.nativeV1.rawValue
        }
    }
}

/// A fully validated request. `function` is an exact function-start address.
struct AIRSReadOptions: Equatable, Sendable {
    var command: String
    var imageSlot: ScriptValue
    var function: UInt64?
    var model: AIRSReadModel
    var limit: Int
    var cursor: AIRSReadCursor?
}

/// Typed, bounded AR0 coordinator reads: names, catalog entries, schemas and argument parsing.
/// No behavior here touches a store; live execution is `AIRSMCPLive`.
enum AIRSMCPReads {
    static let unwindCommand = "unwind-audit"
    static let swiftErrorCommand = "swift-error-flow"
    /// The single default model; omitted-model parsing and the schema both read this constant.
    static let defaultModel = "v1"
    static let defaultLimit = 100
    static let maximumLimit = 256
    static let maximumCursorBytes = 1_024
    static let maximumImageSelectorBytes = 64
    static let allowedArguments = ["imageSlot", "function", "model", "limit", "cursor"]

    static func handles(_ command: String) -> Bool { command == unwindCommand || command == swiftErrorCommand }

    static let unwindInfo = ScriptingCommandInfo(
        name: unwindCommand,
        summary: "Read the current completed focused-image unwind coordinator report; no audit is started or restarted. Use imageSlot (the roadmap's image), optionally an exact function-start address. Models: v1 (default), v4 only. limit 1..256, default 100. T3 rows/total/isTruncated/nextCursor/sourceComplete. Requires a completed owner-started audit of the selected model.",
        mutates: false, arguments: allowedArguments)

    static let swiftErrorInfo = ScriptingCommandInfo(
        name: swiftErrorCommand,
        summary: "Read focused-image structural Swift error-flow evidence for one exact function start. Uses imageSlot. Models: v1 (default), registerCopiesV2, regionsV1 or outcomeWitnessV2 only by explicit argument. The first async call may compute ephemeral evidence through a coordinator; continuations never compute again. limit 1..256, default 100. T3 nextCursor; outcomeWitnessV2 returns candidate-only canonical witnessJSON strings and never validates eligibility. No source or runtime reconstruction claim.",
        mutates: false, arguments: allowedArguments)

    static func requiredArguments(for command: String) -> [String] {
        command == swiftErrorCommand ? ["imageSlot", "function"] : ["imageSlot"]
    }

    static func allowedModels(for command: String) -> [AIRSReadModel] {
        command == unwindCommand ? [.v1, .v4] : [.v1, .registerCopiesV2, .regionsV1, .outcomeWitnessV2]
    }

    /// Schemas for the arguments this seam owns outright; nil for every other field so the older
    /// Navigator schemas (imageSlot, limit, ...) are unchanged.
    static func sharedArgumentSchema(_ argument: String) -> ScriptValue? {
        switch argument {
        case "function":
            return .object([
                "type": .string("string"), "pattern": .string("^0x[0-9a-fA-F]{1,16}$"),
                "description": .string("Exact function-start virtual address, not a name, interior address or file offset."),
            ])
        case "model":
            return .object([
                "type": .string("string"),
                "enum": .array(AIRSReadModel.allCases.map { .string($0.rawValue) }),
                "default": .string(defaultModel),
                "description": .string("Shared schema: unwind-audit accepts v1/v4; swift-error-flow accepts v1/registerCopiesV2/regionsV1/outcomeWitnessV2. Other combinations are malformedInput."),
            ])
        case "cursor":
            return .object([
                "type": .string("string"), "maxLength": .int(Int64(maximumCursorBytes)),
                "description": .string("Opaque continuation token; copy the continuation field advertised by this command unchanged."),
            ])
        default:
            return nil
        }
    }

    static func validate(command: String, fields: [String: ScriptValue]) throws {
        _ = try parse(command: command, fields: fields)
    }

    static func parse(command: String, arguments: ScriptValue) throws -> AIRSReadOptions {
        guard case .object(let fields) = arguments else {
            throw ToolArgumentError(field: "arguments", detail: "Field 'arguments' must be an object.", expected: "object")
        }
        return try parse(command: command, fields: fields)
    }

    static func parse(command: String, fields: [String: ScriptValue]) throws -> AIRSReadOptions {
        if let unknown = fields.keys.sorted().first(where: { !allowedArguments.contains($0) }) {
            let field = ToolArgumentError.fieldLabel(unknown)
            throw ToolArgumentError(field: field, detail: "Field '\(field)' is not an allowed argument.",
                                    allowed: allowedArguments.sorted())
        }
        let slot = try parseImageSlot(fields["imageSlot"])
        var function: UInt64?
        if let value = fields["function"] {
            function = try parseFunction(value)
        } else if command == swiftErrorCommand {
            throw ToolArgumentError(field: "function", detail: "Field 'function' is required.",
                                    expected: "exact hexadecimal function-start address")
        }
        let allowed = allowedModels(for: command)
        var model = AIRSReadModel(rawValue: defaultModel) ?? .v1
        if let value = fields["model"] {
            guard let text = value.stringValue else {
                throw ToolArgumentError(field: "model", detail: "Field 'model' must be a supported model string.",
                                        expected: "string", allowed: allowed.map(\.rawValue))
            }
            guard let parsed = AIRSReadModel(rawValue: text), allowed.contains(parsed) else {
                throw ToolArgumentError(field: "model", detail: "Field 'model' is not supported by this command.",
                                        expected: "string", allowed: allowed.map(\.rawValue))
            }
            model = parsed
        }
        var limit = defaultLimit
        if let value = fields["limit"] {
            guard case .int(let count) = value else {
                throw ToolArgumentError(field: "limit", detail: "Field 'limit' must be an integer.", expected: "integer")
            }
            guard (1...Int64(maximumLimit)).contains(count) else {
                throw ToolArgumentError(field: "limit", code: .outOfBounds,
                    detail: "Field 'limit' must be between 1 and \(maximumLimit).", expected: "integer",
                    minimum: 1, maximum: Int64(maximumLimit))
            }
            limit = Int(count)
        }
        var cursor: AIRSReadCursor?
        if let value = fields["cursor"] { cursor = try parseCursor(value) }
        return AIRSReadOptions(command: command, imageSlot: slot, function: function, model: model,
                               limit: limit, cursor: cursor)
    }

    private static func parseImageSlot(_ value: ScriptValue?) throws -> ScriptValue {
        guard let value, value != .null else {
            throw ToolArgumentError(field: "imageSlot", detail: "Field 'imageSlot' is required.", expected: "integer or string")
        }
        switch value {
        case .int(let slot):
            guard (0...Int64(Int32.max)).contains(slot) else {
                throw ToolArgumentError(field: "imageSlot", code: .outOfBounds,
                    detail: "Field 'imageSlot' must be between 0 and 2147483647.", minimum: 0, maximum: Int64(Int32.max))
            }
        case .string(let text):
            guard !text.isEmpty else {
                throw ToolArgumentError(field: "imageSlot", detail: "Field 'imageSlot' must not be empty.",
                                        expected: "nonempty image selector")
            }
            guard text.utf8.count <= maximumImageSelectorBytes else {
                throw ToolArgumentError(field: "imageSlot", code: .outOfBounds,
                    detail: "Field 'imageSlot' must contain at most 64 UTF-8 bytes.", maximum: 64)
            }
        default:
            throw ToolArgumentError(field: "imageSlot", detail: "Field 'imageSlot' must be an integer slot or a string selector.",
                                    expected: "integer or string")
        }
        return value
    }

    static func parseFunction(_ value: ScriptValue) throws -> UInt64 {
        let invalid = ToolArgumentError(field: "function",
            detail: "Field 'function' must be 0x followed by 1 to 16 hexadecimal digits.",
            expected: "exact hexadecimal function-start address")
        guard let text = value.stringValue, text.hasPrefix("0x") else { throw invalid }
        let digits = text.dropFirst(2)
        guard (1...16).contains(digits.utf8.count),
              digits.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102) }),
              let address = UInt64(digits, radix: 16) else { throw invalid }
        return address
    }

    private static func parseCursor(_ value: ScriptValue) throws -> AIRSReadCursor {
        let invalid = ToolArgumentError(field: "cursor", detail: "Field 'cursor' is not a valid AR0 continuation token.",
                                        expected: "opaque AR0 continuation token")
        guard let text = value.stringValue else { throw invalid }
        guard text.utf8.count <= maximumCursorBytes else {
            throw ToolArgumentError(field: "cursor", code: .outOfBounds,
                detail: "Field 'cursor' must contain at most 1024 UTF-8 bytes.", maximum: Int64(maximumCursorBytes))
        }
        switch AIRSReadCursor.decode(text) {
        case .success(let cursor): return cursor
        case .failure(.invalidOffset):
            throw ToolArgumentError(field: "cursor", detail: "Field 'cursor' has an invalid offset.",
                                    expected: "nonnegative integer offset")
        case .failure(.malformed): throw invalid
        }
    }
}
