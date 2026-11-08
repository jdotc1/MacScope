import Foundation
@testable import MacScope

// Authored, unrun. Test-only, JSON bytes only; transport callers add one LF.
enum MCPReplyOracleError: Error { case malformedGeneration, invalidUTF8, invalidEnvelope, nonFiniteNumber }

func mcpToolReplyJSONByteCount(
    output: ScriptValue, tool: String, generation: ScriptValue?,
    protocolVersion: MCPResultProtocol, id: ScriptValue?
) throws -> Int {
    try mcpToolReplyOracleFrame(output: output, tool: tool, generation: generation,
                               protocolVersion: protocolVersion, id: id).jsonData().count
}

private func requireFinite(_ value: ScriptValue) throws {
    switch value {
    case .double(let number): if !number.isFinite { throw MCPReplyOracleError.nonFiniteNumber }
    case .array(let items): for item in items { try requireFinite(item) }
    case .object(let fields): for item in fields.values { try requireFinite(item) }
    default: break
    }
}

func mcpToolReplyOracleFrame(
    output: ScriptValue, tool: String, generation: ScriptValue?,
    protocolVersion: MCPResultProtocol, id: ScriptValue?
) throws -> ScriptValue {
    try requireFinite(output)
    guard let compact = String(data: try output.jsonData(), encoding: .utf8) else {
        throw MCPReplyOracleError.invalidUTF8
    }
    let adapted = MCPStructuredResult.successEnvelope(
        protocolVersion: protocolVersion, tool: tool, output: output,
        legacyText: compact, isError: false, generation: nil)
    guard case .object(var envelope) = adapted,
          case .array(var content)? = envelope["content"] else {
        throw MCPReplyOracleError.invalidEnvelope
    }
    if let generation, generation != .null {
        guard case .object(let fragment) = generation,
              Set(fragment.keys) == Set(["metadata", "contentSuffix"]),
              case .object(var metadata)? = fragment["metadata"],
              case .array(let suffix)? = fragment["contentSuffix"] else {
            throw MCPReplyOracleError.malformedGeneration
        }
        for block in suffix {
            guard case .object(let fields) = block,
                  fields["type"] == .string("text"),
                  fields["text"]?.stringValue != nil else {
                throw MCPReplyOracleError.malformedGeneration
            }
        }
        // Adapter metadata wins, especially its scalar/array wrapper marker.
        if case .object(let existing)? = envelope["_meta"] {
            metadata.merge(existing) { _, adapter in adapter }
        }
        content.append(contentsOf: suffix)
        envelope["content"] = .array(content)
        envelope["_meta"] = .object(metadata)
    }
    return .object(["jsonrpc": .string("2.0"), "id": id ?? .null,
                    "result": .object(envelope)])
}

// Synthetic UUID-shaped text, never a captured identifier. The fragment freezes
// the single-generation shape; real capture bridge reconciliation is separate.
func syntheticTypeAtlasGeneration() throws -> ScriptValue {
    let metadata = ScriptValue.object([
        "generation": .string("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")])
    let text = String(data: try metadata.jsonData(), encoding: .utf8)!
    return .object([
        "metadata": metadata,
        "contentSuffix": .array([.object([
            "type": .string("text"), "text": .string(text)])])])
}
