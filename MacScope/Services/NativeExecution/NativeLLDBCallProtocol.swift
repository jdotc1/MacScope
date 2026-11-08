import Foundation

/// Only the native coordinator constructs these commands. User inputs are typed request fields.
struct NativeLLDBCallProgram: Sendable {
    let installationCommands: [String]

    init(source: Data) throws {
        guard !source.isEmpty, source.count <= 65_536, String(data: source, encoding: .utf8) != nil else {
            throw NativeExecutionError.unavailable("The native execution program is missing or exceeds its size limit.")
        }
        let chunks = Self.chunks(source.base64EncodedString(), size: 512)
        installationCommands = ["script __ms_native_source=''" ]
            + chunks.map { "script __ms_native_source+='\($0)'" }
            + ["script import base64; __ms_native_program={}; exec(compile(base64.b64decode(__ms_native_source),'<macscope-native-call>','exec'),__ms_native_program); del __ms_native_source"]
    }

    static func requestCommands(_ request: NativeFunctionCallRequest, anchor: DebuggerLocalProcessInstanceKey,
                                token: String) throws -> [String] {
        let data = try requestData(request, anchor: anchor)
        guard data.count <= 131_072 else { throw NativeExecutionError.invalidRequest("The encoded call request exceeds its size limit.") }
        let chunks = chunks(data.base64EncodedString(), size: 512)
        return ["script __ms_native_program['begin']('\(token)','\(request.id.uuidString.lowercased())',\(chunks.count),\(data.count))"]
            + chunks.enumerated().map { "script __ms_native_program['append']('\(token)',\($0.offset),'\($0.element)')" }
    }

    static func command(_ operation: Operation, token: String, page: Int? = nil) -> String {
        switch operation {
        case .attach: "script __ms_native_program['attach']('\(token)')"
        case .entry: "script __ms_native_program['reach_entry']('\(token)')"
        case .memory: "script __ms_native_program['prepare_memory']('\(token)')"
        case .call: "script __ms_native_program['call']('\(token)')"
        case .page: "script __ms_native_program['result_page']('\(token)',\(page ?? -1))"
        case .close: "script __ms_native_program['close']('\(token)')"
        }
    }

    enum Operation: String, Sendable { case attach, entry, memory, call, page, close }

    private static func requestData(_ request: NativeFunctionCallRequest, anchor: DebuggerLocalProcessInstanceKey) throws -> Data {
        try request.validate()
        let null = NSNull()
        let arguments: [[String: Any]] = zip(request.prototype.parameterTypes, request.arguments).map { type, argument in
            var wire: [String: Any] = ["type": type.rawValue, "data": null, "address": null]
            switch argument {
            case .integer(let bytes): wire["kind"] = "integer"; wire["data"] = bytes.base64EncodedString()
            case .nullPointer: wire["kind"] = "null"
            case .buffer(let bytes): wire["kind"] = "buffer"; wire["data"] = bytes.base64EncodedString()
            case .imageRegion(let region): wire["kind"] = "image"; wire["address"] = String(region.staticAddress)
            }
            return wire
        }
        let globals = try request.normalizedGlobals().map { region -> [String: Any] in
            ["label": region.name, "address": String(region.staticAddress), "size": region.byteCount]
        }
        let regions = request.image.regions.map { region -> [String: Any] in
            ["name": region.name, "address": String(region.staticAddress), "size": String(region.byteCount), "permissions": region.permissions]
        }
        return try JSONSerialization.data(withJSONObject: [
            "requestID": request.id.uuidString.lowercased(), "path": request.image.canonicalPath,
            "uuid": request.image.uuid.uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            "pid": anchor.processID, "startSeconds": String(anchor.startTime.seconds),
            "startMicroseconds": String(anchor.startTime.microseconds),
            "entry": String(request.image.entryAddress), "function": String(request.staticFunctionAddress),
            "regions": regions, "returnType": request.prototype.returnType.rawValue,
            "arguments": arguments, "globals": globals, "timeoutMicroseconds": Int(request.timeoutSeconds * 1_000_000)
        ], options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func chunks(_ text: String, size: Int) -> [String] {
        let bytes = Array(text.utf8)
        return stride(from: 0, to: bytes.count, by: size).map { offset in
            String(decoding: bytes[offset..<min(bytes.count, offset + size)], as: UTF8.self)
        }
    }
}

struct NativeLLDBPhaseReceipt: Decodable, Sendable {
    let schema: Int
    let token: String
    let sequence: Int
    let requestID: String
    let phase: String
    let ok: Bool
    let error: String?
    let pid: Int32?
    let stop: UInt32?
    let function: String?
    let regions: Int?
    let pages: Int?
    let index: Int?
    let count: Int?
    let data: String?
}

enum NativeLLDBCallDecoder {
    static func phase(_ semantic: String, requestID: UUID, token: String, sequence: Int,
                      expectedPhase: String) throws -> NativeLLDBPhaseReceipt {
        let prefix = "MACSCOPE_NATIVE_V1 "
        let line = semantic.hasSuffix("\n") ? String(semantic.dropLast()) : semantic
        guard line.utf8.count <= 49_152, line.hasPrefix(prefix), !line.contains("\n"), !line.contains("\r") else {
            throw NativeExecutionError.invalidResponse("Native execution returned invalid framing.")
        }
        let raw = Data(line.dropFirst(prefix.count).utf8)
        let value = try strictJSON(raw, maximumBytes: 49_152)
        guard case .object(let fields) = value else {
            throw NativeExecutionError.invalidResponse("Native execution returned a non-object record.")
        }
        let base: Set<String> = ["schema", "token", "sequence", "requestID", "phase", "ok", "error"]
        try requireCanonicalIntegers(fields, keys: ["schema", "sequence", "pid", "stop", "regions", "pages", "index", "count"])
        let receipt = try JSONDecoder().decode(NativeLLDBPhaseReceipt.self, from: raw)
        let extras: Set<String>
        if !receipt.ok { extras = [] }
        else {
            switch expectedPhase {
            case "begin", "close": extras = []
            case "append": extras = ["index"]
            case "attach": extras = ["pid", "stop"]
            case "entry": extras = ["pid", "stop", "function"]
            case "memory": extras = ["pid", "stop", "regions"]
            case "call": extras = ["pid", "pages"]
            case "page": extras = ["index", "count", "data"]
            default: throw NativeExecutionError.invalidResponse("Native execution returned an unexpected phase.")
            }
        }
        guard Set(fields.keys) == base.union(extras), receipt.schema == 1,
              receipt.token == token, receipt.requestID == requestID.uuidString.lowercased(),
              receipt.sequence == sequence, receipt.phase == expectedPhase,
              receipt.error.map({ $0.utf8.count <= 2048 }) ?? true else {
            throw NativeExecutionError.invalidResponse("Native execution returned a stale or malformed phase record.")
        }
        guard receipt.ok else { throw NativeExecutionError.invalidResponse(receipt.error ?? "Native execution failed without a diagnostic.") }
        return receipt
    }

    static func result(_ raw: Data, request: NativeFunctionCallRequest, runtimeFunctionAddress: UInt64) throws -> NativeFunctionCallResult {
        let value = try strictJSON(raw, maximumBytes: 262_144)
        guard case .object(let fields) = value,
              Set(fields.keys) == ["schema", "requestID", "uuid", "function", "outcome", "returnBytes", "memory", "diagnostics", "faultPC"] else {
            throw NativeExecutionError.invalidResponse("Native execution returned an invalid result schema.")
        }
        try requireCanonicalIntegers(fields, keys: ["schema"])
        let wire = try JSONDecoder().decode(ResultWire.self, from: raw)
        guard wire.schema == 1, wire.requestID == request.id.uuidString.lowercased(),
              wire.uuid == request.image.uuid.uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
              let outcome = NativeExecutionOutcome(rawValue: wire.outcome),
              try unsigned(wire.function) == runtimeFunctionAddress,
              wire.memory.count <= 16, wire.diagnostics.count <= 32,
              wire.diagnostics.allSatisfy({ $0.utf8.count <= 2048 }) else {
            throw NativeExecutionError.invalidResponse("Native execution result identity or limits changed.")
        }
        guard case .array(let memoryFields)? = fields["memory"], memoryFields.allSatisfy({ value in
            guard case .object(let fields) = value else { return false }
            return Set(fields.keys) == ["label", "address", "size", "before", "after", "diagnostic"]
                && canonicalInteger(fields["size"])
        }) else { throw NativeExecutionError.invalidResponse("Observed memory contains unknown or missing fields.") }
        let returnValue: NativeFunctionTypedValue?
        if let encoded = wire.returnBytes {
            guard let bytes = canonicalBase64(encoded), request.prototype.returnType != .void else {
                throw NativeExecutionError.invalidResponse("Native execution returned invalid typed bytes.")
            }
            returnValue = try NativeFunctionTypedValue(type: request.prototype.returnType, bytes: bytes)
        } else {
            guard outcome != .completed || request.prototype.returnType == .void else {
                throw NativeExecutionError.invalidResponse("Native execution omitted the typed return value.")
            }
            returnValue = nil
        }
        let expected = request.arguments.enumerated().compactMap { index, argument -> (String, Int)? in
            if case .buffer(let bytes) = argument { return ("Argument \(index + 1)", bytes.count) }
            return nil
        } + (try request.normalizedGlobals()).map { ($0.name, $0.byteCount) }
        guard wire.memory.count == expected.count else { throw NativeExecutionError.invalidResponse("Observed memory inventory changed.") }
        let memory = try wire.memory.enumerated().map { index, region in
            guard region.label == expected[index].0, region.size == expected[index].1,
                  region.diagnostic.map({ $0.utf8.count <= 1024 }) ?? true else {
                throw NativeExecutionError.invalidResponse("Observed memory bounds or labels changed.")
            }
            func bytes(_ encoded: String?) throws -> Data? {
                guard let encoded else { return nil }
                guard let data = canonicalBase64(encoded), data.count == region.size else {
                    throw NativeExecutionError.invalidResponse("Observed memory byte count changed.")
                }
                return data
            }
            let address = try unsigned(region.address)
            guard region.size > 0, UInt64(region.size) <= UInt64.max - address else {
                throw NativeExecutionError.invalidResponse("Observed memory address overflows.")
            }
            return NativeMemoryObservation(id: index, label: region.label, runtimeAddress: address,
                before: try bytes(region.before), after: try bytes(region.after), diagnostic: region.diagnostic)
        }
        return NativeFunctionCallResult(requestID: request.id, imageUUID: request.image.uuid, outcome: outcome,
            runtimeFunctionAddress: try unsigned(wire.function), returnValue: returnValue, memory: memory,
            diagnostics: wire.diagnostics, faultProgramCounter: try wire.faultPC.map(unsigned), cleanupConfirmed: false)
    }

    private static func canonicalInteger(_ value: Phase2ProductionJSONValue?) -> Bool {
        guard case .number(let text)? = value, let integer = UInt64(text) else { return false }
        return String(integer) == text
    }

    private static func requireCanonicalIntegers(_ fields: [String: Phase2ProductionJSONValue], keys: [String]) throws {
        guard keys.allSatisfy({ fields[$0] == nil || canonicalInteger(fields[$0]) }) else {
            throw NativeExecutionError.invalidResponse("Native execution returned a noncanonical integer field.")
        }
    }

    private static func strictJSON(_ raw: Data, maximumBytes: Int) throws -> Phase2ProductionJSONValue {
        do {
            return try Phase2StrictJSONParser().parse(raw, limits: Phase2StrictJSONLimits(
                maximumBytes: maximumBytes, maximumDepth: 8, maximumTokens: 4096, maximumMembersAndElements: 2048))
        } catch { throw NativeExecutionError.invalidResponse("Native execution returned invalid or duplicate JSON fields.") }
    }

    private static func canonicalBase64(_ encoded: String) -> Data? {
        guard let data = Data(base64Encoded: encoded), data.base64EncodedString() == encoded else { return nil }
        return data
    }

    private static func unsigned(_ text: String) throws -> UInt64 {
        guard let value = UInt64(text), String(value) == text else {
            throw NativeExecutionError.invalidResponse("Native execution returned an invalid address.")
        }
        return value
    }

    private struct ResultWire: Decodable {
        let schema: Int
        let requestID: String
        let uuid: String
        let function: String
        let outcome: String
        let returnBytes: String?
        let memory: [MemoryWire]
        let diagnostics: [String]
        let faultPC: String?
    }
    private struct MemoryWire: Decodable {
        let label: String
        let address: String
        let size: Int
        let before: String?
        let after: String?
        let diagnostic: String?
    }
}
