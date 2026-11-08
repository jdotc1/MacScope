import Foundation
import CryptoKit

public enum MCPExecutableValidation {
    /// Streams a selected native executable; a hash is integrity metadata, not code-signing trust.
    public static func sha256(at url: URL) async throws -> String {
        let task = Task.detached(priority: .utility) { try hashFile(at: url) }
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: { task.cancel() }
    }

    static func hashFile(at url: URL) throws -> String {
        guard url.isFileURL else { throw MCPClientError.untrustedExecutable }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber, size.uint64Value <= 536_870_912
        else { throw MCPClientError.untrustedExecutable }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        var digest = SHA256()
        var total = 0
        while true {
            try Task.checkCancellation()
            let data = try file.read(upToCount: 65_536) ?? Data()
            if data.isEmpty { break }
            total += data.count
            guard total <= 536_870_912 else { throw MCPClientError.untrustedExecutable }
            digest.update(data: data)
        }
        let after = try FileManager.default.attributesOfItem(atPath: url.path)
        guard (after[.size] as? NSNumber) == size,
              (after[.systemFileNumber] as? NSNumber) == (attributes[.systemFileNumber] as? NSNumber),
              (after[.modificationDate] as? Date) == (attributes[.modificationDate] as? Date)
        else { throw MCPClientError.untrustedExecutable }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func validate(_ configuration: MCPConnectionConfiguration) async throws {
        try configuration.validate()
        let url = configuration.executableURL
        guard url.standardizedFileURL == url.resolvingSymlinksInPath().standardizedFileURL,
              FileManager.default.isExecutableFile(atPath: url.path)
        else { throw MCPClientError.untrustedExecutable }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        guard permissions & 0o022 == 0 else { throw MCPClientError.untrustedExecutable }
        let digest = try await sha256(at: url)
        guard digest == configuration.expectedExecutableSHA256.lowercased()
        else { throw MCPClientError.untrustedExecutable }
    }
}

enum MCPBoundaryValidation {
    static func canonicalData(_ value: MCPJSONValue, limits: MCPResourceLimits) throws -> Data {
        try validate(value, limits: limits)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard data.count <= limits.maximumMessageBytes else { throw MCPClientError.responseTooLarge }
        return data
    }

    static func schemaDigest(input: MCPJSONValue, output: MCPJSONValue?, limits: MCPResourceLimits) throws -> String {
        let data = try canonicalData(.object(["input": input, "output": output ?? .null]), limits: limits)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func validate(_ value: MCPJSONValue, limits: MCPResourceLimits) throws {
        var stack: [(MCPJSONValue, Int)] = [(value, 0)]
        var nodes = 0
        var bytes = 0
        while let (item, depth) = stack.popLast() {
            nodes += 1
            guard nodes <= limits.maximumJSONNodes, depth <= limits.maximumJSONDepth
            else { throw MCPClientError.responseTooLarge }
            switch item {
            case .data: throw MCPClientError.unsupportedContent
            case .double(let number):
                guard number.isFinite else { throw MCPClientError.invalidArguments }
            case .string(let value): bytes += value.utf8.count
            case .array(let values):
                guard stack.count + values.count <= limits.maximumJSONNodes else { throw MCPClientError.responseTooLarge }
                stack.append(contentsOf: values.map { ($0, depth + 1) })
            case .object(let object):
                guard stack.count + object.count <= limits.maximumJSONNodes else { throw MCPClientError.responseTooLarge }
                for (key, value) in object { bytes += key.utf8.count; stack.append((value, depth + 1)) }
            default: break
            }
            guard bytes <= limits.maximumMessageBytes else { throw MCPClientError.responseTooLarge }
        }
    }

    /// Bounds JSON nesting before Foundation/SDK decoding. No JSON-RPC interpretation occurs here.
    static func validateFrame(_ data: Data, limits: MCPResourceLimits) throws {
        guard !data.isEmpty, data.count <= limits.maximumMessageBytes else { throw MCPClientError.responseTooLarge }
        var depth = 0
        var quoted = false
        var escaped = false
        for byte in data {
            if quoted {
                if escaped { escaped = false }
                else if byte == 92 { escaped = true }
                else if byte == 34 { quoted = false }
            } else if byte == 34 { quoted = true }
            else if byte == 123 || byte == 91 {
                depth += 1
                guard depth <= limits.maximumJSONDepth else { throw MCPClientError.responseTooLarge }
            } else if byte == 125 || byte == 93 { depth -= 1 }
        }
        guard depth == 0, !quoted,
              (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil
        else { throw MCPClientError.malformedMessage }
    }
}
