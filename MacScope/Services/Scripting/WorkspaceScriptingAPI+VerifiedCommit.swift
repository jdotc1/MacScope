import Foundation

/// VA7a-1: the MCP `verified-commit` command (headless journal owner only).
///
/// One name or comment edit at a function entry, committed through
/// `WorkspaceStore.commitVerifiedAnnotationHeadless`: the R2 edit journal line is the commit point
/// (override plus audit record in one fsync'd line), the live install follows in the same MainActor
/// turn, and the document stays dirty until `save-workspace`. A store with a bound document session is
/// refused (`sessionOwnerNotBuilt`; the attach/session owner is VA7a-2). A store without an attached
/// journal is refused (`headlessJournalRequired`).
///
/// Honest disclosure on every reply:
/// - `verificationTier: "journal+live-projection"`: `observed` is re-read from the live store after the
///   commit (never echoed from the request); there is no published-package readback in this owner.
/// - `durability: "journal"`, `publication.scope: "journal-line"`: nothing is saved to the package.
/// - `evidenceQuality: "synthetic-link"`: the audit's evidence links are placeholders until VA9.
/// - `process: "same"`.
///
/// Retry rule: exact retry is keyed on a caller-supplied `operationId`. If the audit already holds that
/// id and the rebuilt request digest (from the recorded stamps) matches, the stored receipt is returned
/// as `existing` and nothing is written; the same id with anything different is `idempotencyConflict`.
/// Without a caller id the tool mints one and a retry is a NEW commit.
extension WorkspaceScriptingAPI {
    nonisolated static let verifiedCommitCommand = "verified-commit"

    /// Largest comment the checkpoint expectation can carry (`VerifiedCheckpointBounds.maximumCommentBytes`).
    nonisolated static let verifiedCommitMaximumNameBytes = 1_024
    nonisolated static let verifiedCommitMaximumCommentBytes = 2_048
    nonisolated static let verifiedCommitMaximumRationaleBytes = 1_024
    /// Typed classes: the same limits the checkpoint expectation and the codec carry.
    nonisolated static let verifiedCommitMaximumAddressTypeBytes = VerifiedCheckpointBounds.maximumTypeNameBytes
    nonisolated static let verifiedCommitMaximumFunctionSignatureBytes = VerifiedCheckpointBounds.maximumSignatureBytes
    nonisolated static let verifiedCommitAllowedFields = ["addressType", "comment", "functionSignature", "name"]
    nonisolated static let verifiedCommitValueDescription = "Non-empty value without leading or trailing whitespace: name at most 1024 UTF-8 bytes on one line; comment at most 2048 UTF-8 bytes; addressType a canonical type name at most 256 UTF-8 bytes resolving to exactly one definition; functionSignature canonical signature JSON at most 16384 UTF-8 bytes. NUL is forbidden; typed values must be a single line."

    nonisolated static var verifiedCommitArguments: [String] {
        var names = ["address", "field", "value", "operationId", "rationale"]
        #if DEBUG
        names.append("harnessFault")
        #endif
        return names
    }

    nonisolated static var verifiedCommitCommands: [DocumentCommand] {
        [
            (ScriptingCommandInfo(
                name: verifiedCommitCommand,
                summary: "Verified commit (headless; needs an attached edit journal): set name, comment or functionSignature at a function entry, or addressType at a non-entry address inside exactly one mapped segment, and record an audit receipt. The journal line is the commit point (override plus receipt in one fsync'd line) and the live store is updated in the same turn; the document stays dirty until `save-workspace`. The reply re-reads `observed` from the live store (never an echo) and reports matched, `verificationTier` journal+live-projection, `durability` journal, `evidenceQuality` synthetic-link (placeholder evidence links until VA9) and a ready `expectationOperation` for `verified-checkpoint` or the headless checkpoint action. A bound document session is refused (attached sessions are not built yet). An indeterminate commit latches the store: restart `--mcp` with the same package and `--journal` to reconcile. Exact retry needs a caller-supplied `operationId`: the same id with the same address, field, value and rationale returns the stored receipt as existing; the same id with anything different is idempotencyConflict. Without `operationId` a retry is a new commit. Non-empty value without leading or trailing whitespace: name at most 1024 UTF-8 bytes on one line; comment at most 2048 UTF-8 bytes; addressType a canonical type name at most 256 UTF-8 bytes resolving to exactly one definition; functionSignature canonical signature JSON at most 16384 UTF-8 bytes. NUL is forbidden; typed values must be a single line.",
                mutates: true, arguments: verifiedCommitArguments
            ), { arguments, store in try verifiedCommitReply(arguments, store: store) }),
        ]
    }

    // MARK: - Arguments

    struct VerifiedCommitParsed {
        let address: UInt64
        let fieldClass: VerifiedFieldClass
        let value: String
        let operationID: UUID?
        let rationale: String
        let harnessFault: Bool
    }

    nonisolated static func verifiedCommitArgumentSchema(_ argument: String) -> ScriptValue {
        switch argument {
        case "address":
            return .object(["oneOf": .array([
                .object(["type": .string("integer"), "minimum": .int(0)]),
                .object(["type": .string("string"), "pattern": .string("^0x[0-9a-fA-F]{1,16}$")])]),
                "description": .string("Address in the primary image: name, comment and functionSignature require a function entry; addressType requires a non-entry address inside exactly one mapped segment.")])
        case "field":
            return .object(["type": .string("string"), "enum": .array([.string("name"), .string("comment"), .string("addressType"), .string("functionSignature")])])
        case "value":
            return .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(Int64(verifiedCommitMaximumFunctionSignatureBytes)),
                "description": .string(verifiedCommitValueDescription)])
        case "operationId":
            return .object(["type": .string("string"), "format": .string("uuid"),
                "description": .string("Optional caller-supplied operation UUID. Exact retry is keyed on it: the same id with the same address, field, value and rationale returns the stored receipt as existing; anything different is idempotencyConflict. Without it a retry is a new commit.")])
        case "rationale":
            return .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(Int64(verifiedCommitMaximumRationaleBytes)),
                "description": .string("Optional audit rationale (default \"\(VerifiedCommitRequestBuilder.defaultRationale)\"). Part of the request digest, so a retry must repeat it.")])
        case "harnessFault":
            #if DEBUG
            return .object(["type": .string("string"), "enum": .array([.string("failBeforeInstall")]),
                "description": .string("Debug harness only (needs MACSCOPE_MCP_HARNESS_TOOLS=1): fail between the journal line and the live install to exercise the indeterminate latch.")])
            #else
            return .object([:])
            #endif
        default:
            return .object([:])
        }
    }

    /// Exact-key, bounded parse shared by the MCP validator and the handler.
    nonisolated static func verifiedCommitParse(_ fields: [String: ScriptValue]) throws -> VerifiedCommitParsed {
        let allowed = verifiedCommitArguments
        if let unknown = fields.keys.sorted().first(where: { !allowed.contains($0) }) {
            let field = ToolArgumentError.fieldLabel(unknown)
            throw ToolArgumentError(field: field, detail: "Field '\(field)' is not an allowed argument.", allowed: allowed.sorted())
        }
        guard let rawAddress = fields["address"], rawAddress != .null else {
            throw ToolArgumentError(field: "address", detail: "Field 'address' is required.", expected: "address string or non-negative integer")
        }
        guard let address = rawAddress.addressValue else {
            throw ToolArgumentError(field: "address", detail: "Field 'address' must be an address string or non-negative integer.",
                                    expected: "address string or non-negative integer")
        }
        guard let rawField = fields["field"], rawField != .null else {
            throw ToolArgumentError(field: "field", detail: "Field 'field' is required.", expected: "string", allowed: verifiedCommitAllowedFields)
        }
        let fieldClass: VerifiedFieldClass
        switch rawField.stringValue {
        case "name"?: fieldClass = .name
        case "comment"?: fieldClass = .comment
        case "addressType"?: fieldClass = .addressType
        case "functionSignature"?: fieldClass = .functionSignature
        default:
            throw ToolArgumentError(field: "field", detail: "Field 'field' must be name, comment, addressType or functionSignature.",
                                    expected: "string", allowed: verifiedCommitAllowedFields)
        }
        guard let rawValue = fields["value"], rawValue != .null else {
            throw ToolArgumentError(field: "value", detail: "Field 'value' is required.", expected: "string")
        }
        guard let value = rawValue.stringValue else {
            throw ToolArgumentError(field: "value", detail: "Field 'value' must be a string.", expected: "string")
        }
        let maximum: Int
        switch fieldClass {
        case .name: maximum = verifiedCommitMaximumNameBytes
        case .comment: maximum = verifiedCommitMaximumCommentBytes
        case .addressType: maximum = verifiedCommitMaximumAddressTypeBytes
        case .functionSignature: maximum = verifiedCommitMaximumFunctionSignatureBytes
        }
        guard value.utf8.count <= maximum else {
            throw ToolArgumentError(field: "value", code: .outOfBounds,
                                    detail: "Field 'value' must contain at most \(maximum) UTF-8 bytes.", maximum: Int64(maximum))
        }
        guard value == value.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            throw ToolArgumentError(field: "value", detail: "Field 'value' must be non-empty without leading or trailing whitespace.",
                                    expected: "string")
        }
        let typed = fieldClass == .addressType || fieldClass == .functionSignature
        guard !value.contains("\0"), fieldClass == .comment || (!value.contains("\n") && !value.contains("\r")) else {
            throw ToolArgumentError(
                field: "value",
                detail: typed ? "Field 'value' must not contain NUL, and an addressType or functionSignature value must be a single line."
                              : "Field 'value' must not contain NUL, and a name must be a single line.",
                expected: "string")
        }
        if fieldClass == .functionSignature {
            // Reject rather than normalize: only canonical text reaches the builder. The decoder's own
            // description is never exposed.
            do { _ = try VerifiedFieldCodec.decodeSignature(value) }
            catch {
                throw ToolArgumentError(field: "value", detail: "Field 'value' must be canonical functionSignature JSON.",
                                        expected: "string")
            }
        }
        var operationID: UUID?
        if let raw = fields["operationId"], raw != .null {
            guard let text = raw.stringValue, let parsed = UUID(uuidString: text) else {
                throw ToolArgumentError(field: "operationId", detail: "Field 'operationId' must be a UUID string.", expected: "string")
            }
            operationID = parsed
        }
        var rationale = VerifiedCommitRequestBuilder.defaultRationale
        if let raw = fields["rationale"], raw != .null {
            guard let text = raw.stringValue else {
                throw ToolArgumentError(field: "rationale", detail: "Field 'rationale' must be a string.", expected: "string")
            }
            guard text.utf8.count <= verifiedCommitMaximumRationaleBytes else {
                throw ToolArgumentError(field: "rationale", code: .outOfBounds,
                                        detail: "Field 'rationale' must contain at most \(verifiedCommitMaximumRationaleBytes) UTF-8 bytes.",
                                        maximum: Int64(verifiedCommitMaximumRationaleBytes))
            }
            guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !text.contains("\0") else {
                throw ToolArgumentError(field: "rationale", detail: "Field 'rationale' must be non-blank text.", expected: "string")
            }
            rationale = text
        }
        var harnessFault = false
        #if DEBUG
        if let raw = fields["harnessFault"], raw != .null {
            guard raw.stringValue == "failBeforeInstall" else {
                throw ToolArgumentError(field: "harnessFault", detail: "Field 'harnessFault' must be failBeforeInstall.",
                                        expected: "string", allowed: ["failBeforeInstall"])
            }
            harnessFault = true
        }
        #endif
        return VerifiedCommitParsed(address: address, fieldClass: fieldClass, value: value, operationID: operationID,
                                    rationale: rationale, harnessFault: harnessFault)
    }

    /// MCP validator entry (seam M4).
    nonisolated static func verifiedCommitValidate(_ fields: [String: ScriptValue]) throws {
        _ = try verifiedCommitParse(fields)
    }

    // MARK: - Reply

    struct VerifiedCommitHarnessFault: Error {}

    @MainActor
    static func verifiedCommitReply(
        _ arguments: ScriptValue, store: WorkspaceStore,
        harnessToolsEnabled: Bool = ProcessInfo.processInfo.environment["MACSCOPE_MCP_HARNESS_TOOLS"] == "1"
    ) throws -> ScriptValue {
        guard case .object(let fields) = arguments else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(
                code: .malformedInput, detail: "arguments must be an object", field: "arguments", expected: "object"))
        }
        let parsed: VerifiedCommitParsed
        do { parsed = try verifiedCommitParse(fields) }
        catch let error as ToolArgumentError { throw ScriptingError.structuredRefusal(error.refusal) }
        if parsed.harnessFault && !harnessToolsEnabled {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(
                code: .preconditionFailed, detail: "harnessFault requires MACSCOPE_MCP_HARNESS_TOOLS=1 in a debug build",
                field: "harnessFault"))
        }
        let key = ImageAddress(slot: store.snapshot.primarySlot, address: parsed.address)
        let operationID = parsed.operationID ?? UUID()
        let requestedField = parsed.fieldClass.rawValue

        func base(_ outcome: String, ok: Bool) -> [String: ScriptValue] {
            ["ok": .bool(ok), "command": .string(verifiedCommitCommand), "outcome": .string(outcome),
             "operationID": .string(operationID.uuidString), "address": .hex(parsed.address),
             "field": .string(requestedField), "requested": .string(parsed.value), "process": .string("same"),
             "writer": .object(["processID": .int(Int64(ProcessInfo.processInfo.processIdentifier)),
                                "workspaceID": .string(store.workspaceID.uuidString),
                                "documentID": .string(store.documentID.uuidString),
                                "installationID": .string(store.documentInstallationID.uuidString)])]
        }
        func refusal(_ code: String, _ detail: String, extra: [String: ScriptValue] = [:]) -> ScriptValue {
            var out = base("refused", ok: false)
            out["error"] = .string(code); out["detail"] = .string(detail)
            for (name, value) in extra { out[name] = value }
            return finish(out)
        }
        func finish(_ fields: [String: ScriptValue]) -> ScriptValue {
            withGeneration(.object(fields), generation: store.snapshot.analysisGenerationID)
        }
        func observedValue() -> String? {
            parsed.fieldClass.value(in: store.snapshot.addressOverrides[key] ?? AddressOverride())
        }
        func disclosed(_ out: inout [String: ScriptValue], digest: String) {
            let observed = observedValue()
            out["receiptRequestDigest"] = .string(digest)
            out["observed"] = observed.map(ScriptValue.string) ?? .null
            out["matched"] = .bool(observed == parsed.value)
            out["verificationTier"] = .string("journal+live-projection")
            out["durability"] = .string("journal")
            out["evidenceQuality"] = .string("synthetic-link")
        }

        if store.hasBoundDocumentSession {
            return refusal("sessionOwnerNotBuilt",
                           "A document session is bound to this store; the attached/session owner of verified-commit is not built yet (VA7a-2).")
        }

        // Exact retry (caller-supplied id only): rebuild the digest from the recorded stamps.
        if parsed.operationID != nil,
           let record = store.verifiedAnnotationAudit.records.first(where: { $0.operationID == operationID }) {
            func stamp(_ identity: VerifiedAnnotationProjectionIdentity) -> VAProjectionStamp {
                VAProjectionStamp(workspaceID: identity.workspaceID, documentID: identity.documentID,
                                  installationID: identity.installationID, revision: identity.revision, digest: identity.digest)
            }
            let rebuilt = try? VerifiedCommitRequestBuilder.requestDigest(
                operationID: operationID, key: key, fieldClass: parsed.fieldClass, value: parsed.value,
                rationale: parsed.rationale, before: stamp(record.body.before))
            guard record.body.decision == .accepted, rebuilt == record.body.requestDigest else {
                return refusal("idempotencyConflict",
                               "operationId is already recorded for a different address, field, value or rationale.")
            }
            var out = base("existing", ok: true)
            disclosed(&out, digest: record.body.requestDigest)
            out["publication"] = .object(["scope": .string("journal-line"), "pendingEditsPersisted": .bool(false),
                                          "documentClean": .bool(!store.hasUnsavedChanges)])
            out["note"] = .string("Nothing was written. The expectationOperation was returned by the original committed reply.")
            return finish(out)
        }

        let baseline = observedValue()
        let request: VerifiedAnnotationCommitRequest
        do {
            request = try VerifiedCommitRequestBuilder.build(
                store: store, key: key, fieldClass: parsed.fieldClass, value: parsed.value,
                operationID: operationID, rationale: parsed.rationale)
        } catch VerifiedCommitRequestBuilder.Failure.notFunctionEntry {
            return refusal("notFunctionEntry", "The address is not the start of a function in the primary image.")
        } catch {
            return refusal("requestBuildFailed", String(describing: error))
        }

        #if DEBUG
        if parsed.harnessFault {
            store.verifiedHeadlessBeforeInstallHookForTesting = { throw VerifiedCommitHarnessFault() }
        }
        defer { if parsed.harnessFault { store.verifiedHeadlessBeforeInstallHookForTesting = nil } }
        #endif

        switch store.commitVerifiedAnnotationHeadless(request) {
        case .committed(_, let info):
            var out = base("committed", ok: true)
            disclosed(&out, digest: request.receipt.requestDigest)
            out["annotationInstalled"] = .bool(info.annotationInstalled)
            out["liveAdvanced"] = .bool(info.liveAdvanced)
            out["journalDegraded"] = .bool(info.journalDegraded)
            out["publication"] = .object([
                "scope": .string("journal-line"), "pendingEditsPersisted": .bool(false),
                "documentClean": .bool(!store.hasUnsavedChanges), "liveAdvanced": .bool(info.liveAdvanced),
                "annotationInstalled": .bool(info.annotationInstalled), "journalDegraded": .bool(info.journalDegraded)])
            if !info.annotationInstalled {
                out["note"] = .string("A later value of the same field won; observed differs from requested and the receipt stays as history.")
            }
            let operation: VerifiedCheckpointExpectation.Operation
            switch parsed.fieldClass {
            case .name, .comment:
                operation = VerifiedCheckpointExpectation.Operation(
                    operationID: operationID, requestDigest: request.receipt.requestDigest, decision: .accepted,
                    slot: key.slot.rawValue, address: key.address, field: requestedField, requested: parsed.value,
                    baseline: baseline, imageSHA256: nil, beforeRevision: request.receipt.before.revision,
                    afterRevision: request.receipt.after?.revision)
            case .addressType:
                operation = .addressType(
                    operationID: operationID, requestDigest: request.receipt.requestDigest, decision: .accepted,
                    slot: key.slot.rawValue, address: key.address, requested: parsed.value, baseline: baseline,
                    imageSHA256: nil, beforeRevision: request.receipt.before.revision,
                    afterRevision: request.receipt.after?.revision)
            case .functionSignature:
                operation = .functionSignature(
                    operationID: operationID, requestDigest: request.receipt.requestDigest, decision: .accepted,
                    slot: key.slot.rawValue, address: key.address, requested: parsed.value, baseline: baseline,
                    imageSHA256: nil, beforeRevision: request.receipt.before.revision,
                    afterRevision: request.receipt.after?.revision)
            }
            if let data = try? JSONEncoder().encode(operation), let value = try? ScriptValue.decode(data) {
                out["expectationOperation"] = value
            }
            return finish(out)
        case .existing:
            var out = base("existing", ok: true)
            disclosed(&out, digest: request.receipt.requestDigest)
            out["note"] = .string("Nothing was written.")
            return finish(out)
        case .refused(let value):
            var extra: [String: ScriptValue] = [:]
            var detail = value.detail ?? value.code.rawValue
            if value.code == .recoveryRequired, let latch = store.verifiedCommitLatch {
                extra = latchFields(latch)
                detail = "A previous verified commit is unresolved. Restart --mcp with the same package and --journal; the replay reconciles it."
            }
            if value.code == .notHeadless { return refusal("sessionOwnerNotBuilt", "A document session is bound to this store (VA7a-2 not built).") }
            return refusal(value.code.rawValue, detail, extra: extra)
        case .indeterminate(let value):
            var out = base("indeterminate", ok: false)
            out["error"] = .string(value.code.rawValue)
            out["detail"] = .string(value.detail ?? value.code.rawValue)
            out["receiptRequestDigest"] = .string(request.receipt.requestDigest)
            out["possiblyCommitted"] = .bool(true)
            out["retrySafe"] = .bool(false)
            out["recovery"] = .string("Restart --mcp with the same package and --journal; the journal replay installs the operation idempotently if it was committed. Do not retry in this process.")
            for (name, field) in latchFields(store.verifiedCommitLatch) { out[name] = field }
            return finish(out)
        }
    }

    @MainActor
    private static func latchFields(_ latch: VerifiedCommitLatch?) -> [String: ScriptValue] {
        guard let latch else { return ["latched": .bool(false)] }
        return ["latched": .bool(true),
                "latch": .object(["operationID": .string(latch.operationID.uuidString),
                                  "requestDigest": .string(latch.requestDigest),
                                  "reason": .string(latch.reason), "isHeadless": .bool(latch.isHeadless)])]
    }
}
