import Foundation

enum MCPRefusalCode: String, Equatable, Sendable {
    case budgetExceeded, cancelled, preconditionFailed, unsupportedToolchain, outOfBounds
    case malformedInput, unknownSubject, unknownFact, conflictsWithAuthority, notReversible
}

struct MCPRefusalBudget: Equatable, Sendable {
    enum Unit: String, Equatable, Sendable {
        case workSteps, rows, bytes, nodes, wallMillis
        case requests
    }
    let unit: Unit
    let limit: Int64
}

struct MCPRefusalFunction: Equatable, Sendable {
    let name: String
    let address: UInt64
}

struct MCPRefusalSection: Equatable, Sendable {
    let name: String
    let start: UInt64
    let end: UInt64
}

struct MCPToolRefusal: Equatable, Sendable {
    var code: MCPRefusalCode
    var detail: String
    var retryable = false
    var field: String? = nil
    var expected: String? = nil
    var allowed: [String]? = nil
    var minimum: Int64? = nil
    var maximum: Int64? = nil
    var budget: MCPRefusalBudget? = nil
    var used: Int64? = nil
    var narrowing: [String]? = nil
    var requestedAddress: UInt64? = nil
    var imageSlot: Int? = nil
    var nearestFunction: MCPRefusalFunction? = nil
    var section: MCPRefusalSection? = nil

    var value: ScriptValue {
        var fields: [String: ScriptValue] = [
            "code": .string(code.rawValue), "detail": .string(detail), "retryable": .bool(retryable),
        ]
        if let field { fields["field"] = .string(field) }
        if let expected { fields["expected"] = .string(expected) }
        if let allowed { fields["allowed"] = .array(allowed.map { .string($0) }) }
        if let minimum { fields["minimum"] = .int(minimum) }
        if let maximum { fields["maximum"] = .int(maximum) }
        if let budget {
            fields["budget"] = .object(["unit": .string(budget.unit.rawValue), "limit": .int(budget.limit)])
            fields["used"] = used.map { .int($0) } ?? .null
        }
        if let requestedAddress {
            fields["requestedAddress"] = .hex(requestedAddress)
            fields["imageSlot"] = imageSlot.map { .int(Int64($0)) } ?? .null
            fields["nearestFunction"] = nearestFunction.map {
                .object(["name": .string($0.name), "address": .hex($0.address)])
            } ?? .null
            fields["section"] = section.map {
                .object(["name": .string($0.name), "start": .hex($0.start), "end": .hex($0.end)])
            } ?? .null
            fields["resolution"] = .string("refused")
        }
        if let narrowing { fields["narrowing"] = .array(narrowing.map { .string($0) }) }
        return .object(["error": .string("refused"), "refusal": .object(fields)])
    }

    var text: String {
        // Every value above is JSON-safe; retain a refusal if encoding itself fails.
        guard let data = try? value.jsonData() else {
            return #"{"error":"refused","refusal":{"code":"preconditionFailed","detail":"Could not encode the refusal.","retryable":false}}"#
        }
        return String(decoding: data, as: UTF8.self)
    }
}

extension MCPToolRefusal {
    static func executionRefusal(_ error: any Error) -> MCPToolRefusal? {
        var refusal: MCPToolRefusal
        if case ScriptingError.structuredRefusal(let carried) = error {
            refusal = carried
        } else if let budget = error as? DecompileBudgetRefusal {
            let detail = budget.errorDescription ?? ""
            switch budget {
            case .tooLarge(let bytes, let blocks):
                if bytes > WorkspaceScriptingAPI.maximumDecompileFunctionBytes {
                    refusal = MCPToolRefusal(code: .budgetExceeded, detail: detail,
                        budget: .init(unit: .bytes, limit: 262_144),
                        used: Int64(clamping: bytes), narrowing: [])
                } else {
                    refusal = MCPToolRefusal(code: .budgetExceeded, detail: detail,
                        budget: .init(unit: .nodes, limit: 8_192),
                        used: Int64(clamping: blocks), narrowing: [])
                }
            case .deadline(let milliseconds):
                refusal = MCPToolRefusal(code: .budgetExceeded, detail: detail,
                    budget: .init(unit: .wallMillis, limit: Int64(clamping: milliseconds)),
                    narrowing: [])
            }
        } else { return nil }
        refusal.detail = String(refusal.detail.prefix(1_024))
        return refusal
    }
}

struct ToolArgumentError: Error, Equatable, Sendable {
    enum Underlying: Equatable, Sendable {
        case invalidArguments
        case scripting(ScriptingError)
    }
    let refusal: MCPToolRefusal
    let underlying: Underlying

    init(field: String, code: MCPRefusalCode = .malformedInput, detail: String,
         expected: String? = nil, allowed: [String]? = nil,
         minimum: Int64? = nil, maximum: Int64? = nil,
         underlying: Underlying = .invalidArguments) {
        self.refusal = MCPToolRefusal(code: code, detail: detail, field: field,
                                     expected: expected, allowed: allowed,
                                     minimum: minimum, maximum: maximum)
        self.underlying = underlying
    }

    var legacyError: any Error {
        switch underlying {
        case .invalidArguments: HeadlessAutomationAuthorityError.invalidArguments
        case .scripting(let error): error
        }
    }

    static func fieldLabel(_ key: String) -> String {
        var result = ""
        var bytes = 0
        for scalar in key.unicodeScalars {
            let text = String(scalar)
            guard bytes + text.utf8.count <= 64 else { break }
            result += text
            bytes += text.utf8.count
        }
        return result
    }
}
