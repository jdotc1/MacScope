import XCTest
@testable import MacScope

/// The testable core of the live AppleScript runtime: the Cocoa-scripting ⇄ `ScriptValue`
/// bridge and the end-to-end command runner (verb + Apple-event arguments → translate →
/// `WorkspaceScriptingAPI.execute` → result). The `NSScriptCommand` shell that reads a real
/// Apple event and resolves the front document is environment-heavy glue and is verified
/// manually; everything it depends on is exercised here without a running app.
@MainActor
final class AppleScriptRuntimeTests: XCTestCase {

    // MARK: - Argument bridge (Cocoa scripting values -> ScriptValue)

    func testBridgeConvertsScalarCocoaArguments() {
        XCTAssertEqual(AppleScriptArgumentBridge.scriptValue(from: "main"), .string("main"))
        XCTAssertEqual(AppleScriptArgumentBridge.scriptValue(from: NSNumber(value: 4096)), .int(4096))
    }

    func testBridgeConvertsRecordAndListArguments() {
        let record: [String: Any] = ["limit": NSNumber(value: 3)]
        XCTAssertEqual(AppleScriptArgumentBridge.scriptValue(from: record), .object(["limit": .int(3)]))
        let list: [Any] = [NSNumber(value: 1), "x"]
        XCTAssertEqual(AppleScriptArgumentBridge.scriptValue(from: list), .array([.int(1), .string("x")]))
    }

    func testBridgeConvertsScriptValueBackToCocoa() {
        XCTAssertEqual(AppleScriptArgumentBridge.cocoaValue(from: .string("hi")) as? String, "hi")
        XCTAssertEqual(AppleScriptArgumentBridge.cocoaValue(from: .int(7)) as? Int, 7)
        let object = AppleScriptArgumentBridge.cocoaValue(from: .object(["k": .int(1)])) as? [String: Any]
        XCTAssertEqual(object?["k"] as? Int, 1)
    }

    // MARK: - End-to-end runner (translate + execute)

    private func makeAPI() -> WorkspaceScriptingAPI {
        WorkspaceScriptingAPI(store: WorkspaceStore.bootstrapForPreviewFixture())
    }

    func testRunnerExecutesReadVerbEndToEnd() throws {
        let info = try AppleScriptCommandRunner.run(verb: "get info", cocoaArguments: [:], api: makeAPI())
        guard case .object = info else {
            return XCTFail("`get info` should return a record/object, got \(info)")
        }
    }

    func testRunnerConvertsAndForwardsArguments() throws {
        // The NSNumber limit must survive the bridge and bound the returned list.
        let result = try AppleScriptCommandRunner.run(
            verb: "get functions",
            cocoaArguments: ["limit": NSNumber(value: 2)],
            api: makeAPI()
        )
        guard case let .array(items) = result else {
            return XCTFail("`get functions` should return a list, got \(result)")
        }
        XCTAssertLessThanOrEqual(items.count, 2)
    }

    func testRunnerRejectsUnsupportedVerb() {
        XCTAssertThrowsError(try AppleScriptCommandRunner.run(verb: "delete everything", cocoaArguments: [:], api: makeAPI())) {
            XCTAssertEqual($0 as? AppleScriptTranslationError, .unsupportedCommand("delete everything"))
        }
    }

    func testRunnerRejectsNonAllowlistedRunCommand() {
        // The generic `run command` escape hatch must not reach a structural/destructive op.
        XCTAssertThrowsError(try AppleScriptCommandRunner.run(
            verb: "run command",
            cocoaArguments: ["command": "mark-as-data"],
            api: makeAPI()
        ))
    }

    // MARK: - Front-document registry (what the NSScriptCommand shell resolves)

    func testScriptingHostExposesActiveStoreAPI() throws {
        // The host is a shared singleton (the running app may have registered a store), so
        // save/restore rather than assuming an initially-empty registry.
        let previous = ScriptingHost.shared.activeStore
        defer { ScriptingHost.shared.activeStore = previous }

        let store = WorkspaceStore.bootstrapForPreviewFixture()
        ScriptingHost.shared.activeStore = store
        let api = try XCTUnwrap(ScriptingHost.shared.activeAPI, "a registered store must expose an API")
        let info = try AppleScriptCommandRunner.run(verb: "get info", cocoaArguments: [:], api: api)
        guard case .object = info else {
            return XCTFail("the resolved front-document API must execute, got \(info)")
        }

        // Clearing the registration drops the API (the no-front-document case the shell guards).
        ScriptingHost.shared.activeStore = nil
        XCTAssertNil(ScriptingHost.shared.activeAPI)
    }

    // MARK: - VI2b: generation disclosure and basedOnGeneration (AppleScript surface)

    private func makeWritableAPI() -> (WorkspaceStore, WorkspaceScriptingAPI) {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "t.bin", path: "/tmp/t.bin", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 0.9)],
            instructions: [InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil)],
            xrefs: [],
            hexBytes: Data()
        )
        let store = WorkspaceStore(workspaceName: "AS", snapshot: snapshot, engine: AnalysisEngine())
        return (store, WorkspaceScriptingAPI(store: store))
    }

    func testVI2bAppleScriptReadDisclosesGenerationAdditively() throws {
        let (store, api) = makeWritableAPI()
        let info = try AppleScriptCommandRunner.run(verb: "get info", cocoaArguments: [:], api: api)
        XCTAssertEqual(info["generation"], .string(store.snapshot.analysisGenerationID.uuidString))
        XCTAssertNotNil(info["functionCount"], "existing keys are unchanged")
        // The generic verb serializes the same object, so the text reply carries it too.
        let translated = try AppleScriptCommandTranslator.translate(command: "run command", parameters: ["command": .string("info")])
        let reply = try AppleScriptArgumentBridge.cocoaReply(
            from: try AppleScriptCommandRunner.execute(translated, api: api), command: "run command")
        XCTAssertTrue((reply as? String ?? "").contains(store.snapshot.analysisGenerationID.uuidString))
        // Arrays keep their legacy shape (no envelope to carry the field).
        let functions = try AppleScriptCommandRunner.run(verb: "get functions", cocoaArguments: [:], api: api)
        XCTAssertNotNil(functions.arrayValue)
    }

    func testVI2bAppleScriptWriteWithCurrentGenerationAppliesAndStaleIsRefused() throws {
        for (verb, command, field) in [("set name", "rename", "name"), ("set comment", "set-comment", "comment")] {
            let (store, api) = makeWritableAPI()
            let initial = store.snapshot.analysisGenerationID
            let first = try AppleScriptCommandRunner.run(verb: verb, cocoaArguments: [
                "at": "0x1000", "to": "first", "basedOnGeneration": initial.uuidString], api: api)
            let next = store.snapshot.analysisGenerationID
            XCTAssertNotEqual(next, initial, command)
            XCTAssertEqual(first["generation"], .string(next.uuidString), command)
            let before = store.snapshot.addressOverrides
            XCTAssertThrowsError(try AppleScriptCommandRunner.run(verb: verb, cocoaArguments: [
                "at": "0x1000", "to": "second", "basedOnGeneration": initial.uuidString], api: api), command) { error in
                XCTAssertEqual(error as? ScriptingError, .staleEvidence(basedOnGeneration: initial, currentGeneration: next))
                let message = error.localizedDescription
                XCTAssertTrue(message.contains("staleEvidence") && message.contains(initial.uuidString) && message.contains(next.uuidString), message)
            }
            XCTAssertEqual(store.snapshot.addressOverrides, before, "refused write is not applied: \(field)")
            XCTAssertEqual(store.snapshot.analysisGenerationID, next)
        }
    }

    func testVI2bAppleScriptRunCommandPassesBasedOnGenerationInArguments() throws {
        let (store, api) = makeWritableAPI()
        let stale = UUID()
        let current = store.snapshot.analysisGenerationID
        XCTAssertThrowsError(try AppleScriptCommandRunner.run(verb: "run command", cocoaArguments: [
            "command": "set-tag",
            "arguments": ["address": "0x1000", "tag": "t", "basedOnGeneration": stale.uuidString] as [String: Any]], api: api)) {
            XCTAssertEqual($0 as? ScriptingError, .staleEvidence(basedOnGeneration: stale, currentGeneration: current))
        }
    }

    func testVI2bAppleScriptLegacyWriteWithoutGenerationStillApplies() throws {
        let (store, api) = makeWritableAPI()
        let before = store.snapshot.analysisGenerationID
        _ = try AppleScriptCommandRunner.run(verb: "set name", cocoaArguments: ["at": "0x1000", "to": "legacy"], api: api)
        XCTAssertNotEqual(store.snapshot.analysisGenerationID, before, "unconditional write applied")
        let name = try AppleScriptCommandRunner.run(verb: "get name at", cocoaArguments: ["at": "0x1000"], api: api)
        XCTAssertEqual(name.stringValue, "legacy")
    }

    func testVI2bSdefDeclaresBasedOnGenerationOnEachWriteVerb() throws {
        let sdef = TestSourceRoot.url.appendingPathComponent("MacScope/Resources/MacScope.sdef")
        let text = try String(contentsOf: sdef, encoding: .utf8)
        XCTAssertEqual(text.components(separatedBy: #"<parameter name="based on generation""#).count - 1, 3)
        XCTAssertEqual(text.components(separatedBy: #"<cocoa key="basedOnGeneration"/>"#).count - 1, 3)
    }

    // MARK: - VI2c: opt-in envelope on `run command`

    func testVI2cRunCommandWithGenerationReturnsTheEnvelopeAndDefaultIsUnchanged() throws {
        let (store, api) = makeWritableAPI()
        let generation = store.snapshot.analysisGenerationID.uuidString
        func text(_ command: String, _ extra: [String: Any]) throws -> String {
            let translated = try AppleScriptCommandTranslator.translate(
                command: "run command", parameters: AppleScriptArgumentBridge.scriptValues(from: ["command": command].merging(extra) { $1 }))
            return try XCTUnwrap(AppleScriptArgumentBridge.cocoaReply(
                from: try AppleScriptCommandRunner.execute(translated, api: api), command: "run command") as? String)
        }
        // Without the option: unchanged (array stays a bare array; object keeps VI2b's additive key).
        let plainArray = try ScriptValue.decode(Data(try text("functions", [:]).utf8))
        XCTAssertNotNil(plainArray.arrayValue)
        let plainOff = try text("functions", ["withGeneration": false])
        XCTAssertEqual(plainOff, try text("functions", [:]))
        XCTAssertEqual(try ScriptValue.decode(Data(try text("info", [:]).utf8))["generation"], .string(generation))
        // With the option: array, scalar and object all carry the captured generation.
        for command in ["functions", "name-at", "info"] {
            let args: [String: Any] = command == "name-at" ? ["arguments": ["address": "0x0"] as [String: Any], "withGeneration": true] : ["withGeneration": true]
            let envelope = try ScriptValue.decode(Data(try text(command, args).utf8))
            XCTAssertEqual(envelope["generation"], .string(generation), command)
            XCTAssertNotNil(envelope["result"], command)
        }
        let enveloped = try ScriptValue.decode(Data(try text("functions", ["withGeneration": true]).utf8))
        XCTAssertNotNil(enveloped["result"]?.arrayValue, "the typed array result is unchanged inside the envelope")
        // The typed get verbs stay bare lists.
        XCTAssertNotNil(try AppleScriptCommandRunner.run(verb: "get functions", cocoaArguments: [:], api: api).arrayValue)
    }

    func testVI2cEnvelopeGenerationAdvancesAfterAWriteAndRejectsNonBooleanOption() throws {
        let (store, api) = makeWritableAPI()
        func envelopeGeneration() throws -> ScriptValue? {
            let translated = try AppleScriptCommandTranslator.translate(
                command: "run command", parameters: ["command": .string("functions"), "withGeneration": .bool(true)])
            return try AppleScriptCommandRunner.execute(translated, api: api)["generation"]
        }
        let first = try envelopeGeneration()
        XCTAssertEqual(first, .string(store.snapshot.analysisGenerationID.uuidString))
        _ = try AppleScriptCommandRunner.run(verb: "set name", cocoaArguments: ["at": "0x1000", "to": "vi2c"], api: api)
        let second = try envelopeGeneration()
        XCTAssertEqual(second, .string(store.snapshot.analysisGenerationID.uuidString))
        XCTAssertNotEqual(first, second)
        XCTAssertThrowsError(try AppleScriptCommandTranslator.translate(
            command: "run command", parameters: ["command": .string("info"), "withGeneration": .string("yes")]))
    }

    func testVI2cSdefDeclaresWithGenerationOnRunCommandOnly() throws {
        let sdef = TestSourceRoot.url.appendingPathComponent("MacScope/Resources/MacScope.sdef")
        let text = try String(contentsOf: sdef, encoding: .utf8)
        XCTAssertEqual(text.components(separatedBy: #"<parameter name="with generation""#).count - 1, 1)
        XCTAssertEqual(text.components(separatedBy: #"<cocoa key="withGeneration"/>"#).count - 1, 1)
        XCTAssertEqual(text.components(separatedBy: "<command name=").count - 1, 9, "no new sdef verbs")
    }
}
