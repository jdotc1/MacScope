import Foundation
import XCTest
@testable import MacScope

// Item 1333: the typed classes (`addressType`, `functionSignature`) on the MCP `verified-commit` tool.
// Contracts follow the 1333 implementation brief, section 6. The helpers below are local copies of the
// private ones in MCPVerifiedCommitTests; they are copied, not lifted, so that file keeps its own.
//
// Not authored here (blocked or held by the ruling): TC09 (real self-spawn), TC11 (size fixture),
// TC14 (typed erase), the ambiguousType subcase of TC06 and the exact 16,384-byte subcase of TC02.
#if DEBUG
@MainActor
final class MCPVerifiedTypedCommitTests: XCTestCase {
    private struct Headless {
        let fixture: VCFixture.Store
        let package: URL
        let journal: URL
        let store: WorkspaceStore
        let key: ImageAddress
        let api: WorkspaceScriptingAPI
    }

    private func headless(attach: Bool = true, types: [String] = ["Header"]) throws -> Headless {
        let fixture = try VCFixture.makeStore(self)
        for name in types { VCFixture.addType(fixture.store, name) }
        let package = fixture.root.appendingPathComponent("Base.mscope")
        _ = try fixture.store.writeDocumentPackageThrowing(to: package)
        let store = try WorkspaceStore.restoredPackage(from: package)
        let journal = fixture.root.appendingPathComponent("edits.journal")
        if attach { try store.attachEditJournal(at: journal) }
        let key = ImageAddress(slot: store.snapshot.primarySlot, address: fixture.base)
        return Headless(fixture: fixture, package: package, journal: journal, store: store, key: key,
                        api: WorkspaceScriptingAPI(store: store))
    }

    private func freshAttach(_ h: Headless) throws -> (store: WorkspaceStore, report: EditJournalReport, key: ImageAddress) {
        let store = try WorkspaceStore.restoredPackage(from: h.package)
        let report = try store.attachEditJournal(at: h.journal)
        return (store, report, ImageAddress(slot: store.snapshot.primarySlot, address: h.fixture.base))
    }

    private func journalRecordCount(_ h: Headless) throws -> Int {
        try EditJournalReader.read(Data(contentsOf: h.journal)).records.count
    }

    /// A non-entry address inside the image, the same target the typed headless tests use.
    private func typedKey(_ h: Headless) -> ImageAddress { h.fixture.other }

    private func args(_ address: UInt64, field: String, value: String,
                      operationId: UUID? = nil, rationale: String? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = ["address": .hex(address), "field": .string(field), "value": .string(value)]
        if let operationId { fields["operationId"] = .string(operationId.uuidString) }
        if let rationale { fields["rationale"] = .string(rationale) }
        return .object(fields)
    }

    private func call(_ h: Headless, _ arguments: ScriptValue) throws -> ScriptValue {
        try h.api.execute("verified-commit", arguments: arguments)
    }

    private func sigText(_ name: String = "p", type: String = "int", returnType: String = "int") throws -> String {
        try VerifiedFieldCodec.canonicalSignature(VCFixture.signature([("tok", name, type)], returnType: returnType))
    }

    private func parseRefusal(_ fields: [String: ScriptValue]) -> MCPToolRefusal? {
        do { _ = try WorkspaceScriptingAPI.verifiedCommitParse(fields); return nil }
        catch let error as ToolArgumentError { return error.refusal }
        catch { return nil }
    }

    private func fields(_ field: String, _ value: String) -> [String: ScriptValue] {
        ["address": .hex(0x1000), "field": .string(field), "value": .string(value)]
    }

    private func keys(_ value: ScriptValue) -> Set<String> {
        if case .object(let object) = value { return Set(object.keys) }
        return []
    }

    private func decodeOperation(_ value: ScriptValue?) throws -> VerifiedCheckpointExpectation.Operation {
        try JSONDecoder().decode(VerifiedCheckpointExpectation.Operation.self, from: try XCTUnwrap(value).jsonData())
    }

    private static let opening = "Verified commit (headless; needs an attached edit journal): set name, comment or functionSignature at a function entry, or addressType at a non-entry address inside exactly one mapped segment, and record an audit receipt."
    private static let addressDescription = "Address in the primary image: name, comment and functionSignature require a function entry; addressType requires a non-entry address inside exactly one mapped segment."
    private static let valueDescription = "Non-empty value without leading or trailing whitespace: name at most 1024 UTF-8 bytes on one line; comment at most 2048 UTF-8 bytes; addressType a canonical type name at most 256 UTF-8 bytes resolving to exactly one definition; functionSignature canonical signature JSON at most 16384 UTF-8 bytes. NUL is forbidden; typed values must be a single line."

    // MARK: TC01 catalog

    func testTC01CatalogEntryListsTheFourClassesInOrder() throws {
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "verified-commit" })
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        XCTAssertEqual(schema["properties"]?["field"]?["enum"],
                       .array([.string("name"), .string("comment"), .string("addressType"), .string("functionSignature")]))
        XCTAssertEqual(schema["required"], .array([.string("address"), .string("field"), .string("value")]))
        XCTAssertEqual(schema["additionalProperties"], .bool(false))
        XCTAssertTrue(info.arguments.contains("basedOnGeneration"), "the decorated catalog keeps basedOnGeneration")
        XCTAssertFalse(MCPAttachExecutor.attachCommands.contains("verified-commit"))
    }

    // MARK: TC02 limits

    func testTC02PerClassByteLimits() throws {
        XCTAssertNil(parseRefusal(fields("addressType", String(repeating: "T", count: 256))))
        let over = try XCTUnwrap(parseRefusal(fields("addressType", String(repeating: "T", count: 257))))
        XCTAssertEqual(over.code, .outOfBounds)
        XCTAssertEqual(over.field, "value")
        XCTAssertEqual(over.maximum, 256)
        XCTAssertEqual(over.detail, "Field 'value' must contain at most 256 UTF-8 bytes.")

        // The byte check wins over the shape check: 16,385 spaces is a bound refusal, not a shape refusal.
        let big = try XCTUnwrap(parseRefusal(fields("functionSignature", String(repeating: " ", count: 16_385))))
        XCTAssertEqual(big.code, .outOfBounds)
        XCTAssertEqual(big.maximum, 16_384)
        XCTAssertEqual(big.detail, "Field 'value' must contain at most 16384 UTF-8 bytes.")

        // Decodable but non-canonical text gets the typed codec failure detail.
        let canonical = try sigText()
        let object = try JSONSerialization.jsonObject(with: Data(canonical.utf8))
        let pretty = String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted]), as: UTF8.self)
        XCTAssertNotEqual(pretty, canonical)
        let single = pretty.replacingOccurrences(of: "\n", with: "")
        for text in [single, "not json"] {
            let refusal = try XCTUnwrap(parseRefusal(fields("functionSignature", text)), text)
            XCTAssertEqual(refusal.detail, "Field 'value' must be canonical functionSignature JSON.")
            XCTAssertEqual(refusal.code, .malformedInput)
            XCTAssertEqual(refusal.field, "value")
            XCTAssertEqual(refusal.expected, "string")
        }
        XCTAssertNil(parseRefusal(fields("functionSignature", canonical)))

        XCTAssertNil(parseRefusal(fields("name", String(repeating: "n", count: 1_024))))
        XCTAssertEqual(parseRefusal(fields("name", String(repeating: "n", count: 1_025)))?.detail,
                       "Field 'value' must contain at most 1024 UTF-8 bytes.")
        XCTAssertNil(parseRefusal(fields("comment", String(repeating: "c", count: 2_048))))
        XCTAssertEqual(parseRefusal(fields("comment", String(repeating: "c", count: 2_049)))?.detail,
                       "Field 'value' must contain at most 2048 UTF-8 bytes.")
    }

    func testTC02FieldDiagnosticsUseTheLexicalAllowedArray() throws {
        let invalid = try XCTUnwrap(parseRefusal(fields("type", "v")))
        XCTAssertEqual(invalid.detail, "Field 'field' must be name, comment, addressType or functionSignature.")
        XCTAssertEqual(invalid.allowed, ["addressType", "comment", "functionSignature", "name"])
        XCTAssertEqual(invalid.expected, "string")
        let missing = try XCTUnwrap(parseRefusal(["address": .hex(0x1000), "value": .string("v")]))
        XCTAssertEqual(missing.detail, "Field 'field' is required.")
        XCTAssertEqual(missing.allowed, ["addressType", "comment", "functionSignature", "name"])
    }

    // MARK: TC03 and TC05 address type commit

    func testTC03AddressTypeCommitAndTC05TypedOperation() throws {
        let h = try headless()
        let id = UUID()
        let reply = try call(h, args(typedKey(h).address, field: "addressType", value: "Header", operationId: id))
        XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
        XCTAssertEqual(reply["outcome"], .string("committed"))
        XCTAssertEqual(reply["field"], .string("addressType"))
        XCTAssertEqual(reply["requested"], .string("Header"))
        XCTAssertEqual(reply["observed"], .string("Header"))
        XCTAssertEqual(reply["matched"], .bool(true))
        XCTAssertEqual(reply["verificationTier"], .string("journal+live-projection"))
        XCTAssertEqual(reply["durability"], .string("journal"))
        XCTAssertEqual(reply["evidenceQuality"], .string("synthetic-link"))
        XCTAssertEqual(h.store.snapshot.addressOverrides[typedKey(h)]?.appliedTypeName, "Header")
        XCTAssertEqual(try journalRecordCount(h), 1)

        let operation = try XCTUnwrap(reply["expectationOperation"])
        XCTAssertEqual(operation["operationID"], .string(id.uuidString))
        XCTAssertEqual(operation["field"], .string("addressType"))
        XCTAssertEqual(operation["fieldClass"], .string("addressType"))
        XCTAssertEqual(operation["requested"], .string("Header"))
        XCTAssertEqual(operation["requestedDigest"], .string(VerifiedAnnotationAuditCodec.sha256Hex(Data("Header".utf8))))
        XCTAssertNil(operation["erase"], "erase is absent, not false")
        XCTAssertNil(operation["baseline"], "no applied type before the commit")
        XCTAssertEqual(operation["requestDigest"], reply["receiptRequestDigest"])
        XCTAssertEqual(try decodeOperation(operation).isTyped, true)
    }

    // MARK: TC04 and TC05 function signature commit

    func testTC04FunctionSignatureCommitCarriesAbsentThenCanonicalBaseline() throws {
        let h = try headless()
        let first = try sigText("a", type: "int", returnType: "int")
        let second = try sigText("b", type: "char *", returnType: "void")
        XCTAssertNotEqual(first, second)

        let one = try call(h, args(h.fixture.base, field: "functionSignature", value: first))
        XCTAssertEqual(one["outcome"], .string("committed"), "\(one)")
        XCTAssertEqual(one["observed"], .string(first))
        XCTAssertEqual(one["matched"], .bool(true))
        let oneOperation = try XCTUnwrap(one["expectationOperation"])
        XCTAssertNil(oneOperation["baseline"], "absent baseline is nil")
        XCTAssertEqual(oneOperation["fieldClass"], .string("functionSignature"))
        XCTAssertEqual(oneOperation["field"], .string("functionSignature"))
        XCTAssertEqual(oneOperation["requestedDigest"], .string(VerifiedAnnotationAuditCodec.sha256Hex(Data(first.utf8))))
        XCTAssertNil(oneOperation["erase"])

        let two = try call(h, args(h.fixture.base, field: "functionSignature", value: second))
        XCTAssertEqual(two["outcome"], .string("committed"), "\(two)")
        XCTAssertEqual(two["expectationOperation"]?["baseline"], .string(first), "a present canonical baseline is byte-equal")
        XCTAssertEqual(try journalRecordCount(h), 2)

        // TC05 schema rule on the decoded operations: name-only is schema 1, typed or mixed is schema 2.
        let name = try call(h, args(h.fixture.base, field: "name", value: "control-name"))
        let nameOperation = try XCTUnwrap(name["expectationOperation"])
        for typedKeyName in ["fieldClass", "requestedDigest", "erase"] {
            XCTAssertNil(nameOperation[typedKeyName], "a name operation keeps its legacy shape: \(typedKeyName)")
        }
        let nameOp = try decodeOperation(nameOperation)
        let typedOp = try decodeOperation(oneOperation)
        XCTAssertEqual(VerifiedCheckpointExpectation.requiredSchemaVersion(for: [nameOp]), 1)
        XCTAssertEqual(VerifiedCheckpointExpectation.requiredSchemaVersion(for: [typedOp]), 2)
        XCTAssertEqual(VerifiedCheckpointExpectation.requiredSchemaVersion(for: [nameOp, typedOp]), 2)
    }

    // MARK: TC06 refusals

    private func assertRefused(_ h: Headless, _ arguments: ScriptValue, error: String, detail: String,
                               line: UInt = #line) throws {
        let before = VCFixture.dump(h.store)
        let count = try journalRecordCount(h)
        let reply = try call(h, arguments)
        XCTAssertEqual(reply["ok"], .bool(false), "\(reply)", line: line)
        XCTAssertEqual(reply["error"], .string(error), "\(reply)", line: line)
        XCTAssertEqual(reply["detail"], .string(detail), "\(reply)", line: line)
        XCTAssertEqual(VCFixture.dump(h.store), before, line: line)
        XCTAssertEqual(try journalRecordCount(h), count, line: line)
    }

    func testTC06TypedRefusalsLeaveTheStoreAndJournalUnchanged() throws {
        let h = try headless()
        try assertRefused(h, args(h.fixture.base, field: "addressType", value: "Header"),
                          error: "candidateRejected", detail: "functionEntryTarget")
        try assertRefused(h, args(typedKey(h).address, field: "addressType", value: "NoSuchType"),
                          error: "candidateRejected", detail: "unresolvedType")
        try assertRefused(h, args(0x10, field: "addressType", value: "Header"),
                          error: "candidateRejected", detail: "addressOutsideSegments")
        try assertRefused(h, args(typedKey(h).address, field: "functionSignature", value: try sigText()),
                          error: "candidateRejected", detail: "notFunctionEntry")
        let empty = try VerifiedFieldCodec.canonicalSignature(FunctionSignatureOverride())
        try assertRefused(h, args(h.fixture.base, field: "functionSignature", value: empty),
                          error: "invalidReceipt", detail: "signature-no-effect")
        // Codec-level subcases never reach the store.
        XCTAssertNotNil(parseRefusal(fields("addressType", "")))
        XCTAssertNotNil(parseRefusal(fields("addressType", String(repeating: "T", count: 257))))
        XCTAssertNotNil(parseRefusal(fields("addressType", "bad\u{0}name")))
    }

    // MARK: TC07 retry

    func testTC07ExactRetryAndConflicts() throws {
        let h = try headless()
        let id = UUID()
        let first = try call(h, args(typedKey(h).address, field: "addressType", value: "Header", operationId: id))
        XCTAssertEqual(first["outcome"], .string("committed"), "\(first)")
        let bytes = try Data(contentsOf: h.journal)

        let retry = try call(h, args(typedKey(h).address, field: "addressType", value: "Header", operationId: id))
        XCTAssertEqual(retry["ok"], .bool(true), "\(retry)")
        XCTAssertEqual(retry["outcome"], .string("existing"))
        XCTAssertEqual(retry["receiptRequestDigest"], first["receiptRequestDigest"])
        XCTAssertNil(retry["expectationOperation"], "the retry path adds no operation")
        XCTAssertEqual(try Data(contentsOf: h.journal), bytes)

        VCFixture.addType(h.store, "Other")
        for changed in [args(typedKey(h).address, field: "addressType", value: "Other", operationId: id),
                        args(typedKey(h).address, field: "functionSignature", value: try sigText(), operationId: id),
                        args(typedKey(h).address, field: "comment", value: "Header", operationId: id)] {
            let conflict = try call(h, changed)
            XCTAssertEqual(conflict["error"], .string("idempotencyConflict"), "\(conflict)")
            XCTAssertEqual(conflict["detail"],
                           .string("operationId is already recorded for a different address, field, value or rationale."))
            XCTAssertEqual(try Data(contentsOf: h.journal), bytes)
        }
    }

    // MARK: TC08 changed surface

    func testTC08NameAndCommentControlsKeepTheirReplyShape() throws {
        let h = try headless()
        let name = try call(h, args(h.fixture.base, field: "name", value: "control-name"))
        let comment = try call(h, args(h.fixture.base, field: "comment", value: "control comment"))
        let type = try call(h, args(typedKey(h).address, field: "addressType", value: "Header"))
        let signature = try call(h, args(h.fixture.base, field: "functionSignature", value: try sigText()))
        for reply in [name, comment, type, signature] { XCTAssertEqual(reply["outcome"], .string("committed"), "\(reply)") }
        XCTAssertEqual(keys(type), keys(name), "no response-shape extension for the typed classes")
        XCTAssertEqual(keys(signature), keys(name))
        XCTAssertEqual(keys(comment), keys(name))
        XCTAssertEqual(name["observed"], .string("control-name"))
        XCTAssertEqual(comment["observed"], .string("control comment"))
        XCTAssertEqual(try journalRecordCount(h), 4)
    }

    func testTC08BoundSessionRefusesATypedCallUnchanged() async throws {
        let session = try await VCSession(test: self)
        defer { session.session.close() }
        let before = VCFixture.dump(session.store)
        let api = WorkspaceScriptingAPI(store: session.store)
        let reply = try api.execute("verified-commit", arguments: args(session.fixture.base + 4, field: "addressType", value: "Header"))
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["error"], .string("sessionOwnerNotBuilt"), "\(reply)")
        XCTAssertEqual(VCFixture.dump(session.store), before)
    }

    // MARK: TC10 harness fault

    func testTC10FailBeforeInstallLatchesForEachTypedClass() throws {
        let cases: [(field: String, value: String, atEntry: Bool)] = [
            ("addressType", "Header", false), ("functionSignature", try sigText(), true)]
        for (field, value, atEntry) in cases {
            let h = try headless()
            let target = atEntry ? h.fixture.base : typedKey(h).address
            var arguments: [String: ScriptValue] = ["address": .hex(target), "field": .string(field),
                                                    "value": .string(value), "harnessFault": .string("failBeforeInstall")]
            let reply = try WorkspaceScriptingAPI.verifiedCommitReply(.object(arguments), store: h.store, harnessToolsEnabled: true)
            XCTAssertEqual(reply["ok"], .bool(false), "\(field) \(reply)")
            XCTAssertEqual(reply["outcome"], .string("indeterminate"), "\(field) \(reply)")
            XCTAssertEqual(reply["error"], .string("committedLiveNotInstalled"), field)
            XCTAssertEqual(reply["latched"], .bool(true), field)
            XCTAssertEqual(try journalRecordCount(h), 1, field)
            arguments["harnessFault"] = nil
            let next = try WorkspaceScriptingAPI.verifiedCommitReply(.object(arguments), store: h.store, harnessToolsEnabled: true)
            XCTAssertEqual(next["error"], .string("recoveryRequired"), "\(field) \(next)")
            h.store.detachEditJournal()?.close()
            let fresh = try freshAttach(h)
            XCTAssertEqual(fresh.report.replayed, 1, field)
        }
    }

    // MARK: TC12 save

    func testTC12SaveWorkspacePersistsTypedReceiptsAndRotatesJournal() throws {
        let h = try headless()
        let typeID = UUID()
        let signatureID = UUID()
        let text = try sigText()
        XCTAssertEqual(try call(h, args(typedKey(h).address, field: "addressType", value: "Header", operationId: typeID))["outcome"],
                       .string("committed"))
        XCTAssertEqual(try call(h, args(h.fixture.base, field: "functionSignature", value: text, operationId: signatureID))["outcome"],
                       .string("committed"))
        _ = try h.api.execute("save-workspace", arguments: .object([:]))
        let reopened = try MacScopeDocumentPackage.openPackage(from: h.package)
        XCTAssertEqual(reopened.manifest.verifiedAnnotationAudit?.records.map(\.operationID), [typeID, signatureID])
        let reopenedType = ImageAddress(slot: reopened.snapshot.primarySlot, address: typedKey(h).address)
        let reopenedEntry = ImageAddress(slot: reopened.snapshot.primarySlot, address: h.fixture.base)
        XCTAssertEqual(reopened.snapshot.addressOverrides[reopenedType]?.appliedTypeName, "Header")
        XCTAssertEqual(VerifiedFieldClass.functionSignature.value(
            in: reopened.snapshot.addressOverrides[reopenedEntry] ?? AddressOverride()), text)
        XCTAssertEqual(try journalRecordCount(h), 0, "rotation retired the records that carried the receipts")
        h.store.detachEditJournal()?.close()
    }

    // MARK: TC13 literals

    func testTC13SummaryDescriptionsAndOwnedArgumentsMatchTheLiterals() throws {
        let owned = WorkspaceScriptingAPI.verifiedCommitCommands[0].0
        XCTAssertTrue(owned.summary.hasPrefix(Self.opening), owned.summary)
        XCTAssertTrue(owned.summary.hasSuffix(Self.valueDescription), "closing sentence is the value description")
        XCTAssertEqual(owned.arguments, ["address", "field", "value", "operationId", "rationale", "harnessFault"])
        XCTAssertFalse(owned.arguments.contains("basedOnGeneration"), "added by the decoration, not owned")
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "verified-commit" })
        XCTAssertTrue(info.arguments.contains("basedOnGeneration"))
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        XCTAssertEqual(schema["properties"]?["address"]?["description"], .string(Self.addressDescription))
        XCTAssertEqual(schema["properties"]?["value"]?["description"], .string(Self.valueDescription))
        XCTAssertEqual(schema["properties"]?["value"]?["maxLength"], .int(16_384))
    }

    // MARK: TC16 typed value shape

    func testTC16TypedValueShapeIsRejectedNotNormalized() throws {
        let shape = "Field 'value' must be non-empty without leading or trailing whitespace."
        let single = "Field 'value' must not contain NUL, and an addressType or functionSignature value must be a single line."
        let h = try headless()
        let before = VCFixture.dump(h.store)
        for field in ["addressType", "functionSignature"] {
            for (value, detail) in [("", shape), (" padded ", shape), ("padded\n", shape),
                                    ("a\u{0}b", single), ("a\nb", single), ("a\rb", single)] {
                let refusal = try XCTUnwrap(parseRefusal(fields(field, value)), "\(field) \(value.debugDescription)")
                XCTAssertEqual(refusal.field, "value")
                XCTAssertEqual(refusal.code, .malformedInput)
                XCTAssertEqual(refusal.expected, "string")
                XCTAssertEqual(refusal.detail, detail, "\(field) \(value.debugDescription)")
                XCTAssertThrowsError(try call(h, args(typedKey(h).address, field: field, value: value)))
            }
        }
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertTrue(h.store.snapshot.addressOverrides.isEmpty)
        XCTAssertEqual(try journalRecordCount(h), 0)
    }
}
#endif
