import Foundation

/// Only an explicit offer of the structured-results version changes the wire shape.
/// Unknown offers fall back to our supported legacy version; absence is not consent.
enum MCPResultProtocol: String, Sendable {
    case legacy = "2024-11-05"
    case structured = "2025-06-18"

    static func negotiate(_ offered: ScriptValue?) -> Self {
        offered?.stringValue == Self.structured.rawValue ? .structured : .legacy
    }

    var instructionSuffix: String {
        self == .structured
            ? "\nFor protocol 2025-06-18, successful tool data is in structuredContent instead of the first content block; non-object results use {result: value} with _meta[\"macscope/resultWrapper\"] equal to \"result\", while errors retain their legacy text."
            : ""
    }
}

/// This is an envelope adapter, not a command-result adapter. Callers retain the existing
/// serialization/half-budget admission and pass exactly that output and legacy text.
enum MCPStructuredResult {
    static let wrapperMarker = "macscope/resultWrapper"
    static let maximumSummaryBytes = 320
    // Must equal MCPFrameAdmission.response's parser depth; the admission test pins this.
    static let responseFrameDepth = 64

    static func maximumOutputDepth(
        protocolVersion: MCPResultProtocol, isError: Bool, output: ScriptValue
    ) -> Int {
        guard protocolVersion == .structured && !isError else {
            return ScriptValue.maximumEncodingDepth
        }
        if case .object = output { return responseFrameDepth - 2 }
        return responseFrameDepth - 3
    }

    /// Tool names have already passed the existing <=256 UTF-8-byte admission.
    /// The ASCII suffix is under 64 bytes, so the total is <=320 bytes; no result is copied.
    static func shortText(tool: String) -> String {
        "\(tool): success; data is in structuredContent."
    }

    static func successEnvelope(
        protocolVersion: MCPResultProtocol,
        tool: String,
        output: ScriptValue,
        legacyText: String,
        isError: Bool,
        generation: ScriptingGenerationCapture? = nil,
        note: ScriptValue? = nil,
        noteText: String? = nil
    ) -> ScriptValue {
        let structured = protocolVersion == .structured && !isError
        var content: [ScriptValue] = [
            .object(["type": .string("text"),
                     "text": .string(structured ? shortText(tool: tool) : legacyText)])
        ]
        if let noteText {
            content.append(.object(["type": .string("text"), "text": .string(noteText)]))
        }
        if let generation { content = generation.appendingGeneration(to: content) }
        var fields: [String: ScriptValue] = ["content": .array(content), "isError": .bool(isError)]
        if let generation { fields["_meta"] = generation.metadata }
        if let note { fields["note"] = note }
        if structured {
            if case .object = output {
                fields["structuredContent"] = output
            } else {
                fields["structuredContent"] = .object(["result": output])
                var metadata: [String: ScriptValue] = [:]
                if case .object(let existing)? = fields["_meta"] { metadata = existing }
                metadata[wrapperMarker] = .string("result")
                fields["_meta"] = .object(metadata)
            }
        }
        return .object(fields)
    }
}
