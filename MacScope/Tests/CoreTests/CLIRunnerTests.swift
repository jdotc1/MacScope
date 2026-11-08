import Foundation
import XCTest
@testable import MacScope

final class CLIRunnerTests: XCTestCase {
    func testProductionOutputLimitIsAtLeast64MiB() {
        XCTAssertGreaterThanOrEqual(CLIRunner.Limits.production.maximumOutputBytes, 64 * 1_024 * 1_024)
    }

    @MainActor
    func testTypedReadScriptRecordsCLIProposalAndAppAuthorization() throws {
        let binary = URL(fileURLWithPath: "/bin/ls")
        guard FileManager.default.fileExists(atPath: binary.path) else { throw XCTSkip("no /bin/ls") }
        let script = Data(#"[{"command":"read-evidence","arguments":{"operation":"workspace.summary"}}]"#.utf8)
        let output = try CLIRunner.execute(scriptData: script, binaryURL: binary)
        let result = try XCTUnwrap(try ScriptValue.decode(output).arrayValue?.first)
        XCTAssertEqual(result["status"]?.stringValue, "accepted")
        XCTAssertEqual(result["proposingPrincipal"]?.stringValue, "cli")
        XCTAssertEqual(result["authorizingPrincipal"]?.stringValue, "app")
        XCTAssertNotNil(result["facts"]?["loadedImageCount"]?.stringValue)
    }

    func testRequestParsing() {
        let parsed = CLIRunner.request(from: ["app", "--run-script", "/tmp/s.json", "/bin/ls"])
        XCTAssertEqual(
            parsed?.script.path,
            URL(fileURLWithPath: "/tmp/s.json").resolvingSymlinksInPath().standardizedFileURL.path
        )
        XCTAssertEqual(
            parsed?.binary.path,
            URL(fileURLWithPath: "/bin/ls").resolvingSymlinksInPath().standardizedFileURL.path
        )

        XCTAssertNil(CLIRunner.request(from: ["app"]))
        XCTAssertNil(CLIRunner.request(from: ["app", "--run-script"]))             // no paths
        XCTAssertNil(CLIRunner.request(from: ["app", "--run-script", "/tmp/s.json"])) // script but no binary
        XCTAssertNil(CLIRunner.request(from: ["app", "--mcp", "/bin/ls"]))         // different mode
        XCTAssertNil(CLIRunner.request(from: ["app", "x", "--run-script", "s", "b"])) // flag not in the mode slot
        XCTAssertNil(CLIRunner.request(from: ["app", "--run-script", "s", "b", "extra"]))

        // A positional value that looks like another mode's flag stays a positional value
        // (it is NOT reinterpreted): this parses as CLI mode with the "--mcp=…" token as
        // the script path, NOT hijacked into MCP mode.
        let tricky = CLIRunner.request(from: ["app", "--run-script", "--mcp=/etc/passwd", "/bin/ls"])
        XCTAssertNotNil(tricky)
        XCTAssertEqual(
            tricky?.binary.path,
            URL(fileURLWithPath: "/bin/ls").resolvingSymlinksInPath().standardizedFileURL.path
        )
        XCTAssertEqual(tricky?.script.lastPathComponent, "passwd")
        // ...and the MCP parser refuses to claim that same argv (the anti-hijack guarantee).
        XCTAssertNil(MCPLauncher.requestedBinary(from: ["app", "--run-script", "--mcp=/etc/passwd", "/bin/ls"]))
    }

    func testRequestAndLoaderBindCanonicalScriptWithAnExactByteLimit() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-script-identity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("script.json")
        let alias = directory.appendingPathComponent("alias.json")
        let bytes = Data(#"[{"command":"info"}]"#.utf8)
        try bytes.write(to: target)
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: target)

        let request = try XCTUnwrap(CLIRunner.request(from: [
            "app", "--run-script", alias.path, "/bin/ls",
        ]))
        XCTAssertEqual(request.script.path, target.standardizedFileURL.path)
        XCTAssertEqual(try CLIRunner.loadScript(at: request.script, maximumBytes: bytes.count), bytes)
        XCTAssertThrowsError(try CLIRunner.loadScript(at: request.script, maximumBytes: bytes.count - 1)) {
            XCTAssertTrue($0 is CLIRunnerError)
        }
    }

    @MainActor
    func testExecuteRunsBatchScriptAgainstRealBinary() throws {
        // End-to-end: load a real Mach-O and run a multi-step batch script through the
        // same command surface the MCP server uses — the full `--run-script` path minus
        // the file read and process exit.
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        guard FileManager.default.fileExists(atPath: lsURL.path) else { throw XCTSkip("no /bin/ls") }

        let script = #"""
        [
          {"command": "info"},
          {"command": "functions", "arguments": {"limit": 2}}
        ]
        """#
        let output = try CLIRunner.execute(scriptData: Data(script.utf8), binaryURL: lsURL)
        let decoded = try ScriptValue.decode(output)

        // Results come back as an array — one entry per step, in order.
        let results = try XCTUnwrap(decoded.arrayValue)
        XCTAssertEqual(results.count, 2)
        XCTAssertNotNil(results[0]["functionCount"], "first step is `info`")
        let functions = try XCTUnwrap(results[1].arrayValue, "second step is `functions`")
        XCTAssertLessThanOrEqual(functions.count, 2, "limit:2 is honored")
        XCTAssertFalse(functions.isEmpty, "/bin/ls has functions")
    }

    @MainActor
    func testExecuteThrowsOnMalformedScript() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        guard FileManager.default.fileExists(atPath: lsURL.path) else { throw XCTSkip("no /bin/ls") }
        // A script must be a JSON array of steps, not an object.
        XCTAssertThrowsError(try CLIRunner.execute(scriptData: Data(#"{"command":"info"}"#.utf8), binaryURL: lsURL))
    }

    @MainActor
    func testExecuteRejectsDuplicateJSONKeysAndDeniedFilesystemCommands() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        guard FileManager.default.fileExists(atPath: lsURL.path) else { throw XCTSkip("no /bin/ls") }
        let duplicate = Data(#"[{"command":"info","command":"functions"}]"#.utf8)
        XCTAssertThrowsError(try CLIRunner.execute(scriptData: duplicate, binaryURL: lsURL))

        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-authority-escape-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }
        let denied = Data(#"[{"command":"save-patched-binary","arguments":{"path":"\#(destination.path)"}}]"#.utf8)
        XCTAssertThrowsError(try CLIRunner.execute(scriptData: denied, binaryURL: lsURL))
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    @MainActor
    func testExecuteBoundsInputOutputAndRejectsLateResults() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        guard FileManager.default.fileExists(atPath: lsURL.path) else { throw XCTSkip("no /bin/ls") }
        let script = Data(#"[{"command":"info"}]"#.utf8)

        XCTAssertThrowsError(try CLIRunner.execute(
            scriptData: script,
            binaryURL: lsURL,
            limits: .init(
                maximumScriptBytes: script.count - 1,
                maximumOutputBytes: 8_192,
                maximumCommandDurationNanoseconds: 1_000
            )
        )) { XCTAssertTrue($0 is CLIRunnerError) }

        XCTAssertThrowsError(try CLIRunner.execute(
            scriptData: script,
            binaryURL: lsURL,
            limits: .init(
                maximumScriptBytes: 1_024,
                maximumOutputBytes: 8,
                maximumCommandDurationNanoseconds: .max
            )
        )) { XCTAssertEqual($0 as? CLIRunnerError, .outputTooLarge) }

        var ticks: [UInt64] = [10, 12]
        XCTAssertThrowsError(try CLIRunner.execute(
            scriptData: script,
            binaryURL: lsURL,
            limits: .init(
                maximumScriptBytes: 1_024,
                maximumOutputBytes: 8_192,
                maximumCommandDurationNanoseconds: 1
            ),
            monotonicNow: { ticks.removeFirst() }
        )) { error in
            XCTAssertEqual(error as? CLIRunnerError, .commandDeadlineExceeded)
        }
    }

    // MARK: - VI2b: generation disclosure and basedOnGeneration (CLI surface)

    @MainActor
    func testVI2bCLIReadCarriesGenerationAdditively() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        XCTAssertTrue(FileManager.default.fileExists(atPath: lsURL.path), "/bin/ls is required")
        let script = #"[{"command": "info"}, {"command": "info"}, {"command": "functions", "arguments": {"limit": 1}}]"#
        let results = try XCTUnwrap(ScriptValue.decode(
            try CLIRunner.execute(scriptData: Data(script.utf8), binaryURL: lsURL)).arrayValue)
        let first = try XCTUnwrap(results[0]["generation"]?.stringValue)
        XCTAssertNotNil(UUID(uuidString: first))
        XCTAssertEqual(results[1]["generation"]?.stringValue, first, "same snapshot, same generation")
        XCTAssertNotNil(results[0]["functionCount"], "existing keys are unchanged")
        XCTAssertNotNil(results[2].arrayValue, "array results keep their legacy shape")
    }

    @MainActor
    func testVI2bCLIWriteMismatchFailsTypedAndLegacyOmissionIsUnchanged() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        XCTAssertTrue(FileManager.default.fileExists(atPath: lsURL.path), "/bin/ls is required")
        let stale = UUID()
        let script = #"[{"command": "rename", "arguments": {"address": "0x1000", "name": "x", "basedOnGeneration": "\#(stale.uuidString)"}}]"#
        XCTAssertThrowsError(try CLIRunner.execute(scriptData: Data(script.utf8), binaryURL: lsURL)) { error in
            guard case ScriptingError.staleEvidence(let basedOn, let current)? = error as? ScriptingError else {
                return XCTFail("expected staleEvidence, got \(error)")
            }
            XCTAssertEqual(basedOn, stale)
            let message = error.localizedDescription
            XCTAssertTrue(message.contains("staleEvidence") && message.contains(stale.uuidString) && message.contains(current.uuidString), message)
        }
    }

    @MainActor
    func testVI2bCLIStepAuthorityHonorsCurrentGenerationAndLegacyOmission() throws {
        let store = WorkspaceStore.bootstrapForPreviewFixture()
        let api = WorkspaceScriptingAPI(store: store)
        let address = try XCTUnwrap(store.snapshot.functions.first?.startAddress)
        let initial = store.snapshot.analysisGenerationID
        func step(_ extra: [String: ScriptValue]) throws -> ScriptValue {
            let capture = ScriptingGenerationCapture()
            let arguments = ScriptValue.object(["address": .hex(address), "name": .string("vi2b")].merging(extra) { $1 })
            let raw = try ScriptingGenerationCapture.$current.withValue(capture) {
                try HeadlessAutomationAuthority.execute(command: "rename", arguments: arguments, api: api, proposingPrincipal: .cli)
            }
            return capture.disclosing(raw)
        }
        let applied = try step(["basedOnGeneration": .string(initial.uuidString)])
        let next = store.snapshot.analysisGenerationID
        XCTAssertEqual(applied["generation"], .string(next.uuidString))
        let before = store.snapshot.addressOverrides
        XCTAssertThrowsError(try step(["name": .string("other"), "basedOnGeneration": .string(initial.uuidString)])) {
            XCTAssertEqual($0 as? ScriptingError, .staleEvidence(basedOnGeneration: initial, currentGeneration: next))
        }
        XCTAssertEqual(store.snapshot.addressOverrides, before, "refused write is not applied")
        _ = try step(["name": .string("legacy")])
        XCTAssertNotEqual(store.snapshot.addressOverrides, before, "omission keeps the unconditional write")
    }

    // MARK: - VI2c: opt-in generation envelope (CLI)

    func testVI2cRequestParsingAcceptsOnlyTheExactTrailingFlag() {
        let plain = ["app", "--run-script", "/tmp/s.json", "/bin/ls"]
        XCTAssertNotNil(CLIRunner.request(from: plain))
        XCTAssertFalse(CLIRunner.wantsGeneration(in: plain))
        let flagged = plain + ["--with-generation"]
        XCTAssertNotNil(CLIRunner.request(from: flagged))
        XCTAssertTrue(CLIRunner.wantsGeneration(in: flagged))
        XCTAssertNil(CLIRunner.request(from: plain + ["--with-generations"]))
    }

    @MainActor
    private func vi2cScript(_ steps: [String]) -> Data { Data("[\(steps.joined(separator: ","))]".utf8) }

    private static let vi2cReadSteps = [
        #"{"command":"functions","arguments":{"limit":2}}"#,
        #"{"command":"name-at","arguments":{"address":"0x0"}}"#,
        #"{"command":"info"}"#,
    ]

    @MainActor
    func testVI2cDefaultOutputIsByteIdenticalForArrayAndScalarSteps() throws {
        let store = try MCPLauncher.makeBoundStore(binaryURL: URL(fileURLWithPath: "/bin/ls"))
        let script = vi2cScript(Self.vi2cReadSteps)
        let implicit = try CLIRunner.execute(scriptData: script, binaryURL: URL(fileURLWithPath: "/bin/ls"), preparedStore: store)
        let explicitOff = try CLIRunner.execute(scriptData: script, binaryURL: URL(fileURLWithPath: "/bin/ls"), withGeneration: false, preparedStore: store)
        XCTAssertEqual(implicit, explicitOff, "withGeneration: false is the default and changes no byte")
        let results = try XCTUnwrap(ScriptValue.decode(implicit).arrayValue)
        XCTAssertNotNil(results[0].arrayValue, "array step keeps the bare array shape")
        XCTAssertNil(results[0]["generation"])
        XCTAssertNil(results[1].arrayValue); XCTAssertNil(results[1]["generation"], "scalar step has no envelope key")
        XCTAssertNil(results[1]["result"])
        XCTAssertNotNil(results[2]["generation"], "object steps keep VI2b's additive key")
    }

    @MainActor
    func testVI2cEnvelopeCarriesTheReadGenerationForArrayScalarAndObjectSteps() throws {
        let store = try MCPLauncher.makeBoundStore(binaryURL: URL(fileURLWithPath: "/bin/ls"))
        let generation = store.store.snapshot.analysisGenerationID.uuidString
        let output = try CLIRunner.execute(scriptData: vi2cScript(Self.vi2cReadSteps),
            binaryURL: URL(fileURLWithPath: "/bin/ls"), withGeneration: true, preparedStore: store)
        let results = try XCTUnwrap(ScriptValue.decode(output).arrayValue)
        XCTAssertEqual(results.count, 3)
        for (index, envelope) in results.enumerated() {
            XCTAssertEqual(envelope["generation"], .string(generation), "step \(index)")
            XCTAssertNotNil(envelope["result"], "step \(index) wraps the result")
        }
        XCTAssertNotNil(results[0]["result"]?.arrayValue, "array result is unchanged inside the envelope")
        XCTAssertNil(results[1]["result"]?.arrayValue); XCTAssertNil(results[1]["result"]?["result"])
        XCTAssertNotNil(results[2]["result"]?["functionCount"], "object result keeps its keys")
        XCTAssertEqual(results[2]["result"]?["generation"], .string(generation), "object result keeps VI2b's additive key")
    }

    @MainActor
    func testVI2cRenameBetweenStepsAdvancesTheEnvelopeGeneration() throws {
        let store = try MCPLauncher.makeBoundStore(binaryURL: URL(fileURLWithPath: "/bin/ls"))
        let before = store.store.snapshot.analysisGenerationID.uuidString
        let script = vi2cScript([
            #"{"command":"functions","arguments":{"limit":1}}"#,
            #"{"command":"rename","arguments":{"address":"0x1000","name":"vi2c"}}"#,
            #"{"command":"functions","arguments":{"limit":1}}"#,
        ])
        let output = try CLIRunner.execute(scriptData: script, binaryURL: URL(fileURLWithPath: "/bin/ls"),
            withGeneration: true, preparedStore: store)
        let results = try XCTUnwrap(ScriptValue.decode(output).arrayValue)
        let after = store.store.snapshot.analysisGenerationID.uuidString
        XCTAssertNotEqual(before, after)
        XCTAssertEqual(results[0]["generation"], .string(before))
        XCTAssertEqual(results[2]["generation"], .string(after), "the later read reports the post-rename generation")
        XCTAssertNotEqual(results[0]["generation"], results[2]["generation"])
    }

    /// Gap 2. A static script cannot feed one step's output into the next and every `execute` opens
    /// a fresh snapshot with a random generation, so the generation is read from a prepared store
    /// before `execute` (the `preparedStore` seam) and written into the script as a literal.
    @MainActor
    func testVI2cFullExecuteWriteHonorsLiteralGenerationFromAnEarlierRead() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        let store = try MCPLauncher.makeBoundStore(binaryURL: lsURL)
        let read = store.store.snapshot.analysisGenerationID
        func rename(_ name: String, basedOn: UUID) -> Data {
            vi2cScript([#"{"command":"rename","arguments":{"address":"0x1000","name":"\#(name)","basedOnGeneration":"\#(basedOn.uuidString)"}}"#])
        }
        let applied = try CLIRunner.execute(scriptData: rename("first", basedOn: read), binaryURL: lsURL,
            withGeneration: true, preparedStore: store)
        let current = store.store.snapshot.analysisGenerationID
        XCTAssertNotEqual(current, read, "the write advanced the generation")
        let result = try XCTUnwrap(ScriptValue.decode(applied).arrayValue?.first)
        XCTAssertEqual(result["generation"], .string(current.uuidString))
        let overrides = store.store.snapshot.addressOverrides
        XCTAssertThrowsError(try CLIRunner.execute(scriptData: rename("second", basedOn: read), binaryURL: lsURL,
            preparedStore: store)) { error in
            XCTAssertEqual(error as? ScriptingError, .staleEvidence(basedOnGeneration: read, currentGeneration: current))
            let message = error.localizedDescription
            XCTAssertTrue(message.contains("staleEvidence") && message.contains(read.uuidString) && message.contains(current.uuidString), message)
        }
        XCTAssertEqual(store.store.snapshot.addressOverrides, overrides, "the stale write is not applied")
    }
}
