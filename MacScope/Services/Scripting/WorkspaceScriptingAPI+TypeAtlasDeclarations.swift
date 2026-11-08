import Foundation

// SW5 declarations-v1 (dot 1251). This is a retained-fact notation, not compilable Swift/ObjC/C.
// Only format:declarations-v1 enters this file. All limits/refusals below are proposed.
extension WorkspaceScriptingAPI {
    nonisolated static let maximumTypeAtlasDeclarationStringBytes = 8_192
    nonisolated static let maximumTypeAtlasDeclarationBytes = 65_536
    nonisolated static let maximumTypeAtlasDeclarationPageBytes = 196_608
    nonisolated static let maximumTypeAtlasDeclarationJSONBytes = 524_288

    nonisolated static func typeAtlasDeclarationSelected(_ arguments: ScriptValue) throws -> Bool {
        guard let value = arguments["format"], value != .null else { return false }
        guard value == .string("declarations-v1") else {
            throw ScriptingError.invalidArgument("format must be declarations-v1 or null")
        }
        return true
    }

    nonisolated static func typeAtlasDeclarationPage(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void, swiftObjCLinks: Bool
    ) throws -> ScriptValue {
        try checkpoint()
        guard case .object(var fields) = arguments else {
            throw ScriptingError.invalidArgument("arguments must be an object")
        }
        switch fields["page"] {
        case .none, .some(.null), .some(.bool(true)): break
        case .some(.bool(false)):
            throw ScriptingError.invalidArgument("declarations-v1 requires page:true or an omitted page")
        default: throw ScriptingError.invalidArgument("page must be a boolean")
        }
        fields.removeValue(forKey: "format")
        fields["page"] = .bool(true)
        if let cursor = fields["cursor"], cursor != .null {
            fields["cursor"] = try typeAtlasDeclarationCursor(cursor)
        }
        // Re-enter the ORIGINAL page producer. No independent catalog, matching, ordering,
        // omission, linking, preparation or row-admission logic is introduced here.
        guard let page = try typeAtlasPage(.object(fields), snapshot: snapshot,
            checkpoint: checkpoint, swiftObjCLinks: swiftObjCLinks) else {
            throw typeAtlasDeclarationRefusal("The bounded page producer returned no page.",
                unit: .rows, limit: 1, used: 0)
        }
        return try typeAtlasDeclarationResult(page, checkpoint: checkpoint)
    }

    nonisolated static func typeAtlasDeclarationResult(
        _ page: ScriptValue, checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        try checkpoint()
        guard case .object(var fields) = page, let rows = fields["rows"]?.arrayValue else {
            throw typeAtlasDeclarationRefusal("The bounded page has no retained rows array.",
                unit: .rows, limit: 1, used: 0)
        }
        // Defence in depth only: the pin's names-row bound makes this unreachable today.
        // Never mint an offset-zero or non-advancing success if the producer changes later.
        guard !rows.isEmpty || fields["isTruncated"] != .bool(true) else {
            throw typeAtlasDeclarationRefusal("The bounded page made no progress; no declarations returned.",
                unit: .rows, limit: 1, used: 0)
        }
        fields.removeValue(forKey: "rows")
        fields["format"] = .string("declarations-v1")
        fields["text"] = .string(try typeAtlasDeclarationText(rows, checkpoint: checkpoint))
        if let cursor = fields["nextCursor"], cursor != .null {
            fields["nextCursor"] = try typeAtlasDeclarationCursor(cursor)
        }
        let result = ScriptValue.object(fields)
        try checkpoint()
        let size = try result.jsonData().count
        guard size <= maximumTypeAtlasDeclarationJSONBytes else {
            throw typeAtlasDeclarationRefusal("The declaration page exceeds its inner JSON byte limit; no declarations returned.",
                unit: .bytes, limit: maximumTypeAtlasDeclarationJSONBytes, used: size)
        }
        try checkpoint()
        return result
    }

    // SW5 (dot 1251): l1 grammar is unchanged; isolate its 64-bit fingerprint with
    // a nonzero, versioned namespace mask. This involution maps the full old fingerprint
    // bijectively into the declarations-v1/catalog-entry-index-v1 namespace. For identical
    // selectors the old and new values can NEVER equal. Existing FNV collision properties
    // are unchanged; this is continuation identity, not authentication. A format/order
    // revision MUST allocate another mask. Both foreign directions reach the old stale
    // check, rather than changing the old decoder's malformed-cursor diagnostics.
    nonisolated static func typeAtlasDeclarationCursor(_ value: ScriptValue) throws -> ScriptValue {
        let bad = ScriptingError.invalidArgument("malformed cursor")
        guard case .string(let text) = value,
              text.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes,
              let data = Data(base64Encoded: text), data.base64EncodedString() == text,
              let body = String(data: data, encoding: .utf8) else { throw bad }
        var parts = body.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        func decimal(_ text: String) -> Bool {
            !text.isEmpty && text.utf8.allSatisfy { (48...57).contains($0) }
        }
        guard parts.count == 6, parts[0] == "l1", parts[1] == "list-image-types",
              decimal(parts[2]), Int(parts[2]) != nil,
              decimal(parts[3]), let offset = Int(parts[3]), offset > 0,
              UUID(uuidString: parts[4]) != nil, parts[5].utf8.count == 16,
              parts[5].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let fingerprint = UInt64(parts[5], radix: 16) else { throw bad }
        let isolated = String(fingerprint ^ 0x5357350001000001, radix: 16)
        parts[5] = String(repeating: "0", count: 16 - isolated.count) + isolated
        return .string(Data(parts.joined(separator: "|").utf8).base64EncodedString())
    }

    nonisolated static func typeAtlasDeclarationText(
        _ rows: [ScriptValue], checkpoint: () throws -> Void
    ) throws -> String {
        var text = "// declarations-v1; retained facts only; source completeness unknown.\n"
        var bytes = text.utf8.count
        for (index, row) in rows.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            var writer = TypeAtlasDeclarationWriter()
            try writer.declaration(row, checkpoint: checkpoint)
            guard writer.bytes <= maximumTypeAtlasDeclarationPageBytes - bytes else {
                throw typeAtlasDeclarationRefusal("The declaration page exceeds its text byte limit; no declarations returned.",
                    unit: .bytes, limit: maximumTypeAtlasDeclarationPageBytes, used: bytes + writer.bytes)
            }
            text += writer.text
            bytes += writer.bytes
        }
        try checkpoint()
        return text
    }

    nonisolated static func typeAtlasDeclarationRefusal(
        _ detail: String, unit: MCPRefusalBudget.Unit, limit: Int, used: Int
    ) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: detail,
            budget: .init(unit: unit, limit: Int64(limit)), used: Int64(clamping: used),
            narrowing: ["limit", "fields", "kind", "name", "nameContains"]))
    }
}

// All traversal is over the ALREADY bounded, linked ScriptValue rows. Null is unknown,
// empty is empty, and all strings are inert quoted scalar sequences, never source syntax.
private struct TypeAtlasDeclarationWriter {
    var text = ""
    var bytes = 0
    private var nodes = 0

    private mutating func append(_ fragment: String) throws {
        let count = fragment.utf8.count
        guard count <= WorkspaceScriptingAPI.maximumTypeAtlasDeclarationBytes - bytes else {
            throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                "One declaration exceeds its text byte limit; no declarations returned.",
                unit: .bytes, limit: WorkspaceScriptingAPI.maximumTypeAtlasDeclarationBytes,
                used: bytes + count)
        }
        text += fragment
        bytes += count
    }

    private mutating func node(_ checkpoint: () throws -> Void) throws {
        if nodes % WorkspaceScriptingAPI.checkpointInterval == 0 { try checkpoint() }
        nodes += 1
        guard nodes <= WorkspaceScriptingAPI.maximumTypeAtlasRowNodes else {
            throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                "One declaration exceeds its renderer node limit; no declarations returned.",
                unit: .nodes, limit: WorkspaceScriptingAPI.maximumTypeAtlasRowNodes, used: nodes)
        }
    }

    private mutating func quoted(_ value: String, checkpoint: () throws -> Void) throws {
        let cap = WorkspaceScriptingAPI.maximumTypeAtlasDeclarationStringBytes
        let observed = value.utf8.prefix(cap + 1).count
        guard observed <= cap else {
            // Abstention; used is an observed prefix, NOT a claimed original length.
            throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                "One retained string exceeds 8192 UTF-8 bytes; used is an observed prefix, not its full length; no declarations returned.",
                unit: .bytes, limit: cap, used: observed)
        }
        try append("\"")
        for (index, scalar) in value.unicodeScalars.enumerated() {
            if index % WorkspaceScriptingAPI.checkpointInterval == 0 { try checkpoint() }
            switch scalar.value {
            case 0x22: try append("\\\"")
            case 0x5c: try append("\\\\")
            case 0x20...0x7e: try append(String(scalar))
            default: try append("\\u{" + String(scalar.value, radix: 16) + "}")
            }
        }
        try append("\"")
    }

    private mutating func value(_ value: ScriptValue, depth: Int = 0,
                                checkpoint: () throws -> Void) throws {
        try node(checkpoint)
        guard depth < 16 else {
            throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                "One declaration exceeds its nesting depth; no declarations returned.",
                unit: .nodes, limit: 16, used: depth + 1)
        }
        switch value {
        case .null: try append("unknown")
        case .bool(let flag): try append(flag ? "true" : "false")
        case .int(let integer): try append(String(integer))
        case .double(let number):
            guard number.isFinite else {
                throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                    "A retained number is non-finite; no declarations returned.",
                    unit: .nodes, limit: 0, used: 1)
            }
            try append(String(number))
        case .string(let string): try quoted(string, checkpoint: checkpoint)
        case .array(let values):
            try append("[")
            for (index, item) in values.enumerated() {
                if index > 0 { try append("; ") }
                try self.value(item, depth: depth + 1, checkpoint: checkpoint)
            }
            try append("]")
        case .object(let fields):
            try append("{")
            for (index, key) in fields.keys.sorted().enumerated() {
                try node(checkpoint)
                if index > 0 { try append("; ") }
                try quoted(key, checkpoint: checkpoint)
                try append(" = ")
                try self.value(fields[key] ?? .null, depth: depth + 1, checkpoint: checkpoint)
            }
            try append("}")
        }
    }

    mutating func declaration(_ row: ScriptValue, checkpoint: () throws -> Void) throws {
        try node(checkpoint)
        guard case .object(let fields) = row else {
            throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                "A retained row is not an object; no declarations returned.",
                unit: .nodes, limit: 0, used: 1)
        }
        let token: String
        switch fields["kind"]?.stringValue {
        case "swiftClass": token = "swift-class"
        case "swiftStruct": token = "swift-struct"
        case "swiftEnum": token = "swift-enum"
        case "objcClass": token = "objc-class"
        case "objcCategory": token = "objc-category"
        case "objcProtocol": token = "objc-protocol"
        case "userType": token = "user-type(kind=unknown)"
        case "importedType": token = "imported-type"
        default:
            throw WorkspaceScriptingAPI.typeAtlasDeclarationRefusal(
                "A retained row has an unsupported kind; no declarations returned.",
                unit: .nodes, limit: 0, used: 1)
        }
        try append(token + " ")
        try value(fields["name"] ?? .null, checkpoint: checkpoint)
        try append(" {\n")
        if fields["fullRowOmitted"] == .bool(true) {
            try append("  projection = omitted;\n")
        } else if fields["members"] == nil {
            try append("  projection = names-only;\n")
        }
        if let state = fields["swiftMethodTableResolved"] {
            switch state {
            case .bool(true): try append("  method-table = resolved;\n")
            case .bool(false): try append("  method-table = unresolved;\n")
            default: try append("  method-table = unknown;\n")
            }
        }
        // Keep the original table-resolution field too; the label above adds no fact.
        for key in fields.keys.sorted() where key != "kind" && key != "name" {
            try node(checkpoint)
            if (key == "members" || key == "methods"), let items = fields[key]?.arrayValue {
                if items.isEmpty { try append("  " + key + " = [];\n") }
                for item in items {
                    try append(key == "members" ? "  member " : "  method-record ")
                    try value(item, checkpoint: checkpoint)
                    try append(";\n")
                }
            } else {
                try append("  ")
                try quoted(key, checkpoint: checkpoint)
                try append(" = ")
                try value(fields[key] ?? .null, checkpoint: checkpoint)
                try append(";\n")
            }
        }
        try append("}\n")
        try checkpoint()
    }
}
