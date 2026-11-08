import Darwin
import Foundation

/// VA8: the MCP `verified-checkpoint-isolated` command (read-only, not attachable).
///
/// The serving process builds the checkpoint expectation from its own identity plus the driver's
/// `operations`, spawns a child MacScope in the headless `verified-checkpoint` mode, and returns the
/// child's report. The reply says `process: "isolated"` only when code has checked that the report came
/// from the process this server spawned (a different process ID from the server's own), that the pure
/// judge agrees, that the reader was fresh, that it ran the same executable, and that the saved package
/// bytes did not change across the read. Any failed check is a typed refusal that never says `isolated`.
///
/// Runs on the async path (seam W2): the child wait never blocks MainActor. The sync `run` closure
/// refuses with `asyncTransportRequired`.
extension WorkspaceScriptingAPI {
    nonisolated static let verifiedCheckpointIsolatedCommand = "verified-checkpoint-isolated"
    nonisolated static let verifiedCheckpointIsolatedArguments = ["operations", "imageSlot"]

    #if DEBUG
    /// Test seam: replaces the process-spawning runner.
    @MainActor static var verifiedCheckpointChildRunnerForTesting: (any VerifiedCheckpointChildRunning)?
    #endif

    nonisolated static var verifiedCheckpointIsolatedCommands: [DocumentCommand] {
        [
            (ScriptingCommandInfo(
                name: verifiedCheckpointIsolatedCommand,
                summary: "Read-only fresh-process proof: spawns a child MacScope that reads the SAVED package and judges your `operations` (verbatim expectationOperation objects from verified-commit replies, 1 to 256). The server fills the expectation envelope itself. Refuses unsavedChanges (save-workspace first), noSavedPackage, recoveryRequired, attachedSessionUnsupported. Says process isolated only when verified; otherwise a typed refusal. Echoes the judged expectation.",
                mutates: false, arguments: verifiedCheckpointIsolatedArguments
            ), { _, _ in
                throw ScriptingError.structuredRefusal(MCPToolRefusal(
                    code: .preconditionFailed,
                    detail: "asyncTransportRequired: verified-checkpoint-isolated runs only on the async MCP path"))
            }),
        ]
    }

    // MARK: - Arguments

    struct VerifiedCheckpointIsolatedParsed {
        let operations: [VerifiedCheckpointExpectation.Operation]
        let imageSlot: Int?
    }

    nonisolated static func verifiedCheckpointIsolatedArgumentSchema(_ argument: String) -> ScriptValue {
        switch argument {
        case "operations":
            return .object(["type": .string("array"), "minItems": .int(1),
                            "maxItems": .int(Int64(VerifiedCheckpointBounds.maximumOperations)),
                            "items": .object(["type": .string("object")]),
                            "description": .string("expectationOperation objects copied verbatim from verified-commit replies. The envelope (workspace, document, writer ids) is filled by the server and refused here.")])
        case "imageSlot":
            return .object(["type": .string("integer"), "minimum": .int(0), "maximum": .int(Int64(Int32.max))])
        default:
            return .object([:])
        }
    }

    /// Exact-key, bounded parse shared by the MCP validator and the handler.
    nonisolated static func verifiedCheckpointIsolatedParse(_ fields: [String: ScriptValue]) throws -> VerifiedCheckpointIsolatedParsed {
        let allowed = verifiedCheckpointIsolatedArguments
        if let unknown = fields.keys.sorted().first(where: { !allowed.contains($0) }) {
            let field = ToolArgumentError.fieldLabel(unknown)
            throw ToolArgumentError(field: field, detail: "Field '\(field)' is not an allowed argument.", allowed: allowed.sorted())
        }
        guard let raw = fields["operations"], raw != .null else {
            throw ToolArgumentError(field: "operations", detail: "Field 'operations' is required.", expected: "array of objects")
        }
        guard let items = raw.arrayValue else {
            throw ToolArgumentError(field: "operations", detail: "Field 'operations' must be an array.", expected: "array of objects")
        }
        guard !items.isEmpty else {
            throw ToolArgumentError(field: "operations", detail: "Field 'operations' must not be empty.", expected: "array of objects", minimum: 1)
        }
        guard items.count <= VerifiedCheckpointBounds.maximumOperations else {
            throw ToolArgumentError(field: "operations", code: .outOfBounds,
                                    detail: "Field 'operations' must hold at most \(VerifiedCheckpointBounds.maximumOperations) entries.",
                                    maximum: Int64(VerifiedCheckpointBounds.maximumOperations))
        }
        var operations: [VerifiedCheckpointExpectation.Operation] = []
        for (index, item) in items.enumerated() {
            guard case .object = item, let data = try? item.jsonData(),
                  let operation = try? JSONDecoder().decode(VerifiedCheckpointExpectation.Operation.self, from: data) else {
                throw ToolArgumentError(field: "operations[\(index)]",
                                        detail: "Entry \(index) is not an expectationOperation object.", expected: "object")
            }
            operations.append(operation)
        }
        var slot: Int?
        if let rawSlot = fields["imageSlot"], rawSlot != .null {
            guard let value = rawSlot.intValue, value >= 0, value <= Int64(Int32.max) else {
                throw ToolArgumentError(field: "imageSlot", detail: "Field 'imageSlot' must be a non-negative integer.", expected: "integer")
            }
            slot = Int(value)
        }
        if let slot, let stray = operations.first(where: { $0.slot != slot }) {
            throw ToolArgumentError(field: "imageSlot",
                                    detail: "operation \(stray.operationID.uuidString) targets slot \(stray.slot), not imageSlot \(slot)")
        }
        return VerifiedCheckpointIsolatedParsed(operations: operations, imageSlot: slot)
    }

    /// MCP validator entry (seam M4).
    nonisolated static func verifiedCheckpointIsolatedValidate(_ fields: [String: ScriptValue]) throws {
        _ = try verifiedCheckpointIsolatedParse(fields)
    }

    // MARK: - Reply

    func verifiedCheckpointIsolatedReply(_ arguments: ScriptValue) async throws -> ScriptValue {
        guard case .object(let fields) = arguments else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(
                code: .malformedInput, detail: "arguments must be an object", field: "arguments", expected: "object"))
        }
        let parsed: VerifiedCheckpointIsolatedParsed
        do { parsed = try Self.verifiedCheckpointIsolatedParse(fields) }
        catch let error as ToolArgumentError { throw ScriptingError.structuredRefusal(error.refusal) }

        let command = Self.verifiedCheckpointIsolatedCommand
        let generation = store.snapshot.analysisGenerationID
        var artifact: URL?
        func refusal(_ code: String, _ detail: String, extra: [String: ScriptValue] = [:]) -> ScriptValue {
            var out: [String: ScriptValue] = [
                "ok": .bool(false), "command": .string(command), "readOnly": .bool(true),
                "error": .string(code), "detail": .string(detail)]
            for (name, value) in extra { out[name] = value }
            if let artifact { out["artifactPath"] = .string(artifact.path) }
            return Self.withGeneration(.object(out), generation: generation)
        }

        // Admission.
        if store.hasBoundDocumentSession {
            return refusal("attachedSessionUnsupported",
                           "A document session is bound to this store; the isolated checkpoint reads a saved package for a headless store only (VA7a-2).")
        }
        if let latch = store.verifiedCommitLatch {
            return refusal("recoveryRequired",
                           "A previous verified commit is unresolved. Restart --mcp with the same package and --journal; the replay reconciles it.",
                           extra: ["latched": .bool(true),
                                   "latch": .object(["operationID": .string(latch.operationID.uuidString),
                                                     "requestDigest": .string(latch.requestDigest),
                                                     "reason": .string(latch.reason), "isHeadless": .bool(latch.isHeadless)])])
        }
        guard let packageURL = store.documentURL else {
            return refusal("noSavedPackage", "This workspace has no saved package. Call save-workspace with a path first.")
        }
        if store.hasUnsavedChanges {
            return refusal("unsavedChanges",
                           "The workspace has unsaved changes; the child reads only saved bytes. Call save-workspace first.")
        }
        guard let executable = Bundle.main.executableURL else {
            return refusal("executableUnavailable", "The serving process has no executable path to spawn.")
        }

        // Envelope: the server's own identity; the driver cannot supply any of it.
        let writerPID = ProcessInfo.processInfo.processIdentifier
        let expectation = VerifiedCheckpointExpectation(
            schemaVersion: VerifiedCheckpointExpectation.requiredSchemaVersion(for: parsed.operations),
            workspaceID: store.workspaceID, documentID: store.documentID,
            writerInstallationIDs: [store.documentInstallationID], writerProcessID: writerPID,
            operations: parsed.operations)
        let expectationData: Data
        do { expectationData = try expectation.encoded() }
        catch let invalid as VerifiedCheckpointInvalid {
            return refusal("expectationInvalid", invalid.reason)
        }
        guard expectationData.count <= VerifiedCheckpointBounds.maximumRequestFileBytes else {
            return refusal("expectationTooLarge",
                           "The expectation exceeds \(VerifiedCheckpointBounds.maximumRequestFileBytes) bytes.",
                           extra: ["maximum": .int(Int64(VerifiedCheckpointBounds.maximumRequestFileBytes))])
        }
        let expectationValue = (try? ScriptValue.decode(expectationData)) ?? .null

        func observe() async -> WorkspacePackageExternalVersion? {
            try? await Task.detached { try WorkspacePackageVersionProbe().observeSynchronously(packageURL) }.value
        }
        guard let before = await observe(), before.condition == .valid else {
            return refusal("isolationNotEstablished", "The saved package did not observe as a valid package before the read.",
                           extra: ["reason": .string("package-not-valid-before-read")])
        }

        let runner: any VerifiedCheckpointChildRunning
        #if DEBUG
        runner = Self.verifiedCheckpointChildRunnerForTesting ?? ProcessVerifiedCheckpointChildRunner()
        #else
        runner = ProcessVerifiedCheckpointChildRunner()
        #endif
        let started = ContinuousClock.now
        let child: VerifiedCheckpointChildResult
        do {
            child = try await runner.run(executable: executable, workspace: packageURL, expectation: expectationData,
                                         timeout: ProcessVerifiedCheckpointChildRunner.defaultTimeout)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return refusal("isolatedReaderNoReport", "The child reader could not be run: \(error)")
        }
        artifact = child.directory
        let elapsed = started.duration(to: .now)
        let elapsedMs = Int64(elapsed.components.seconds) * 1_000 + Int64(elapsed.components.attoseconds / 1_000_000_000_000_000)

        if child.timedOut {
            return refusal("isolatedReaderTimedOut", "The child reader exceeded its deadline and was terminated.",
                           extra: ["childPID": .int(Int64(child.pid))])
        }
        guard let resultData = child.resultJSON,
              let result = try? ScriptValue.decode(resultData), case .object(let report) = result,
              let readerPID = report["readerProcessID"]?.intValue,
              let processIsolated = report["processIsolated"]?.boolValue,
              let allPass = report["allOperationsPass"]?.boolValue,
              let reportedOperations = report["operations"]?.arrayValue else {
            return refusal("isolatedReaderNoReport", "The child produced no usable result.json.",
                           extra: ["childExitStatus": .int(Int64(child.exitStatus)),
                                   "childStderr": .string(child.stderrFirstLine)])
        }

        guard let after = await observe(), after.condition == .valid,
              after.manifestSHA256 == before.manifestSHA256,
              after.validatedContentSHA256 == before.validatedContentSHA256 else {
            return refusal("packageChangedDuringCheckpoint",
                           "The saved package changed while the child read it; the read proves nothing.")
        }

        func notEstablished(_ reason: String) -> ScriptValue {
            refusal("isolationNotEstablished", "The report cannot be shown to come from a separate fresh reader.",
                    extra: ["reason": .string(reason), "readerProcessID": .int(readerPID),
                            "spawnedProcessID": .int(Int64(child.pid)), "writerProcessID": .int(Int64(writerPID))])
        }
        if readerPID != Int64(child.pid) { return notEstablished("reader-process-is-not-the-spawned-process") }
        if readerPID == Int64(writerPID) || child.pid == writerPID { return notEstablished("reader-process-is-the-serving-process") }
        if !processIsolated { return notEstablished("judge-reports-not-isolated") }
        if report["packageOutcome"]?["code"]?.stringValue == "installationNotFresh" { return notEstablished("installation-not-fresh") }
        let readerExecutable = report["executable"]?.stringValue
        let sameExecutable = readerExecutable == executable.path
            || readerExecutable.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
                == executable.resolvingSymlinksInPath().path
        if !sameExecutable { return notEstablished("reader-executable-differs") }

        // Isolation established.
        let passed = allPass
        let confirmed = reportedOperations.filter { $0["outcome"]?.stringValue == "confirmed" }.count
        let passing = reportedOperations.filter { $0["pass"]?.boolValue == true }.count
        let unexpected = report["unexpectedOperationIDs"]?.arrayValue?.count ?? 0
        var out: [String: ScriptValue] = [
            "ok": .bool(true), "command": .string(command), "process": .string("isolated"), "readOnly": .bool(true),
            "passed": .bool(passed), "allOperationsPass": .bool(allPass),
            "summary": .object(["expected": .int(Int64(parsed.operations.count)), "confirmed": .int(Int64(confirmed)),
                                "passing": .int(Int64(passing)), "unexpected": .int(Int64(unexpected))]),
            "operations": .array(reportedOperations),
            "unexpectedOperationIDs": report["unexpectedOperationIDs"] ?? .array([]),
            "packageOutcome": report["packageOutcome"] ?? .null,
            "notes": report["notes"] ?? .array([]),
            "isolation": .object([
                "writerProcessID": .int(Int64(writerPID)), "writerProcessIDSource": .string("serving-process"),
                "readerProcessID": .int(readerPID),
                "readerInstallationID": report["readerInstallationID"] ?? .null,
                "readerExecutable": readerExecutable.map(ScriptValue.string) ?? .null,
                "sameExecutable": .bool(true), "readerOpenedStore": .bool(false), "readerAttachedJournal": .bool(false),
                "source": .string("saved-package-on-disk"), "package": .string(packageURL.path),
                "packageObservation": .object([
                    "manifestSHA256": before.manifestSHA256.map(ScriptValue.string) ?? .null,
                    "validatedContentSHA256": before.validatedContentSHA256.map(ScriptValue.string) ?? .null]),
                "packageStableAcrossRead": .bool(true), "writerStoreCleanAtAdmission": .bool(true),
                "writerJournalAttached": .bool(store.editJournal != nil)]),
            "expectation": expectationValue,
            "childExitStatus": .int(Int64(child.exitStatus)), "elapsedMs": .int(elapsedMs),
            "bounds": .object([
                "maximumOperations": .int(Int64(VerifiedCheckpointBounds.maximumOperations)),
                "maximumRequestBytes": .int(Int64(VerifiedCheckpointBounds.maximumRequestFileBytes)),
                "childTimeoutSeconds": .int(Int64(ProcessVerifiedCheckpointChildRunner.defaultTimeout))]),
        ]
        if passed {
            try? FileManager.default.removeItem(at: child.directory)
        } else {
            out["artifactPath"] = .string(child.directory.path)
        }
        return Self.withGeneration(.object(out), generation: generation)
    }
}
