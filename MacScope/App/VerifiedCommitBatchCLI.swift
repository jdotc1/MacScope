#if DEBUG
import Darwin
import Foundation

/// VA-G acceptance harness (debug builds only), the writer half of the VA4 fresh-process check:
/// `MacScope --verified-commit-batch <request.json>`.
///
/// It calls the PRODUCTION commit path (`WorkspaceDocumentSession.commitVerifiedAnnotation`, the real
/// publisher, reader and `NativeAnnotationProjector`) for a batch of verified type and signature edits on a
/// workspace made from a real app binary, saves the `.mscope`, and writes the expectation file the existing
/// `--headless-workspace-acceptance` action `verified-checkpoint` consumes in a second process.
/// No MCP or Scripting surface, no Models change, no release-build code (ruling 10). The receipts are built
/// here, as the CoreTests build them: no verifier or evidence ledger is wired yet (VA5), so the evidence
/// links are synthetic and say nothing about evidence quality.
///
/// Request (strict JSON, absolute paths, at most 65,536 bytes):
///   plan:   {"action":"plan","binary":"/abs/exe","output":"/abs/new-dir","include":["0x100157ebc"],"functionCount":10}
///   commit: {"action":"commit","binary":"/abs/exe","output":"/abs/new-dir","plan":"/abs/functions.json",
///            "injectReadbackMismatch":false}
/// `output` must not exist. Prints one summary line, writes `result.json` there, exits 0 only when every
/// requested step succeeded. No retry.
@MainActor
enum VerifiedCommitBatchCLI {
    static let flag = "--verified-commit-batch"
    nonisolated static let deadlineSeconds = 590.0
    nonisolated static let maximumDeadlineSeconds = 7200.0

    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    struct Request: Equatable {
        enum Action: String { case plan, commit }
        let action: Action
        let binary: URL
        let output: URL
        let plan: URL?
        let include: [UInt64]
        let functionCount: Int
        let injectReadbackMismatch: Bool
        /// Optional in-process deadline override (record-only runs on very large binaries).
        let deadlineSeconds: Double

        static func decode(_ data: Data) throws -> Request {
            guard case let .object(value) = try HeadlessJSON.decode(data, maximumBytes: 65_536),
                  Set(value.keys).isSubset(of: ["action", "binary", "output", "plan", "include",
                                                "functionCount", "injectReadbackMismatch", "deadlineSeconds"]),
                  case let .string(rawAction) = value["action"], let action = Action(rawValue: rawAction),
                  case let .string(binary) = value["binary"], case let .string(output) = value["output"],
                  isAbsolute(binary), isAbsolute(output) else {
                throw Failure("invalid-verified-commit-batch-request")
            }
            var plan: URL?
            switch action {
            case .commit:
                guard case let .string(path) = value["plan"], isAbsolute(path) else {
                    throw Failure("invalid-verified-commit-batch-plan")
                }
                plan = URL(fileURLWithPath: path).standardizedFileURL
                guard value["include"] == nil, value["functionCount"] == nil else {
                    throw Failure("invalid-verified-commit-batch-request")
                }
            case .plan:
                guard value["plan"] == nil, value["injectReadbackMismatch"] == nil else {
                    throw Failure("invalid-verified-commit-batch-request")
                }
            }
            var include: [UInt64] = []
            if let raw = value["include"] {
                guard case let .array(items) = raw, items.count <= 16 else {
                    throw Failure("invalid-verified-commit-batch-include")
                }
                for item in items {
                    guard case let .string(text) = item, text.hasPrefix("0x"),
                          let address = UInt64(text.dropFirst(2), radix: 16) else {
                        throw Failure("invalid-verified-commit-batch-include")
                    }
                    include.append(address)
                }
            }
            var count = 10
            if let raw = value["functionCount"] {
                guard case let .int(number) = raw, (1...64).contains(number) else {
                    throw Failure("invalid-verified-commit-batch-function-count")
                }
                count = Int(number)
            }
            var deadline = VerifiedCommitBatchCLI.deadlineSeconds
            if let raw = value["deadlineSeconds"] {
                guard case let .int(number) = raw, number >= 60, Double(number) <= VerifiedCommitBatchCLI.maximumDeadlineSeconds else {
                    throw Failure("invalid-verified-commit-batch-deadline")
                }
                deadline = Double(number)
            }
            var inject = false
            if let raw = value["injectReadbackMismatch"] {
                guard case let .bool(flag) = raw else { throw Failure("invalid-verified-commit-batch-inject") }
                inject = flag
            }
            let binaryURL = URL(fileURLWithPath: binary).resolvingSymlinksInPath().standardizedFileURL
            let outputURL = URL(fileURLWithPath: output).standardizedFileURL
            guard binaryURL != outputURL, !outputURL.path.hasPrefix(binaryURL.path + "/") else {
                throw Failure("invalid-verified-commit-batch-paths")
            }
            return Request(action: action, binary: binaryURL, output: outputURL, plan: plan,
                           include: include, functionCount: count, injectReadbackMismatch: inject,
                           deadlineSeconds: deadline)
        }

        private static func isAbsolute(_ path: String) -> Bool {
            path.hasPrefix("/") && !path.contains("\0") && path.utf8.count < 4096
        }
    }

    /// The request path when this reserved flag is the first argument. Malformed use must exit, never
    /// fall through into SwiftUI.
    static func requestPath(from arguments: [String]) -> String? {
        guard arguments.dropFirst().first == flag else { return nil }
        guard arguments.count == 3, arguments[2].hasPrefix("/") else {
            FileHandle.standardError.write(Data("MacScope verified-commit-batch: invalid-arguments\n".utf8))
            exit(EX_USAGE)
        }
        return arguments[2]
    }

    // MARK: Plan file

    struct Plan: Codable, Equatable {
        struct Entry: Codable, Equatable {
            let index: Int
            let name: String
            let address: UInt64
            let addressHex: String
            /// Type edit target: inside the function, not an entry (the type class refuses entries).
            let typeAddress: UInt64
            let typeAddressHex: String
            let typeName: String
            /// Canonical signature text for the signature edit at `address`.
            let signature: String
        }
        let schema: Int
        let binary: String
        let slotRaw: Int
        let rule: String
        let notes: [String]
        let functions: [Entry]
    }

    static let selectionRule = """
        functions of the primary slice in ascending startAddress order; eligible = name is not sub_<hex>, \
        function entry, size >= 8, start+4 inside one mapped segment and not an entry, no existing override at \
        start or start+4; take the first N eligible; each --include address that is a function start is added \
        first (then the first eligible fill up to N); type edit at start+4, signature edit at start
        """

    /// Timestamped progress line on stderr (record-only timing).
    static func progress(_ text: String) {
        FileHandle.standardError.write(Data("PROGRESS \(Date().ISO8601Format()) \(text)\n".utf8))
    }

    // MARK: Entry

    /// The process-wide hard deadline. The earlier `DispatchQueue.global().asyncAfter` form never fired on a
    /// 3540 s deadline under a 3600 s outer `timeout`: libdispatch may coalesce that timer by up to
    /// min(delta / 10, 60 s), and an AppKit process with no activity assertion is App Nap eligible, so the
    /// fire window reached the outer kill. This arms a strict, zero-leeway timer on its own queue, and the
    /// caller holds a latency-critical activity for the whole run.
    nonisolated final class ProcessDeadline: @unchecked Sendable {
        private let timer: DispatchSourceTimer

        /// Arms the timer; `onFire` runs on a private queue once `seconds` have elapsed.
        init(seconds: Double, onFire: @escaping @Sendable () -> Void) {
            let queue = DispatchQueue(label: "macscope.verified-commit-batch.deadline", qos: .userInitiated)
            timer = DispatchSource.makeTimerSource(flags: .strict, queue: queue)
            timer.schedule(deadline: .now() + seconds, leeway: .nanoseconds(0))
            timer.setEventHandler(handler: onFire)
            timer.resume()
        }

        deinit { timer.cancel() }

        /// Async-signal-safe exit path: one `write(2)` and `_exit`, no stdio, no atexit handlers, no locks.
        static func writeAndExit() -> Never {
            let line = Array("verified-commit-batch-process-deadline\n".utf8)
            _ = line.withUnsafeBufferPointer { Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count) }
            Darwin._exit(EX_TEMPFAIL)
        }
    }

    /// Held for the whole process so App Nap and timer coalescing cannot delay the deadline.
    private nonisolated(unsafe) static var runActivity: NSObjectProtocol?
    private nonisolated(unsafe) static var processDeadline: ProcessDeadline?

    static func run(requestPath: String) -> Never {
        runActivity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiated, .latencyCritical], reason: "verified-commit-batch")
        Task { @MainActor in
            do {
                let data = try CLIRunner.loadScript(at: URL(fileURLWithPath: requestPath), maximumBytes: 65_536)
                let request = try Request.decode(data)
                processDeadline = ProcessDeadline(seconds: request.deadlineSeconds) { ProcessDeadline.writeAndExit() }
                let manager = FileManager.default
                guard !manager.fileExists(atPath: request.output.path) else {
                    throw Failure("verified-commit-batch-output-must-be-new")
                }
                try manager.createDirectory(at: request.output, withIntermediateDirectories: false)
                let outcome: (summary: String, passed: Bool)
                switch request.action {
                case .plan: outcome = try await runPlan(request)
                case .commit: outcome = try await runCommit(request)
                }
                print(outcome.summary)
                Darwin.exit(outcome.passed ? EXIT_SUCCESS : 1)
            } catch {
                FileHandle.standardError.write(Data("MacScope verified-commit-batch: \(error)\n".utf8))
                Darwin.exit(1)
            }
        }
        dispatchMain()
    }

    private static func boundStore(_ binary: URL) async throws -> WorkspaceStore {
        let bound = try await MCPLauncher.makeBoundStoreInBackground(binaryURL: binary, status: MCPStartupStatus())
        bound.store.recents = QuietRecents()
        return bound.store
    }

    // MARK: plan

    private static func runPlan(_ request: Request) async throws -> (summary: String, passed: Bool) {
        let started = ContinuousClock.now
        let store = try await boundStore(request.binary)
        let snapshot = store.snapshot
        let slot = snapshot.primarySlot
        let functions = (snapshot.analysis(in: slot)?.functions ?? []).sorted { $0.startAddress < $1.startAddress }
        func typeTarget(_ function: FunctionSummary) -> UInt64? {
            guard function.endAddress >= function.startAddress &+ 8 else { return nil }
            let address = function.startAddress + 4
            let key = ImageAddress(slot: slot, address: address)
            guard let entry = try? NativeAddressFacts.entry(snapshot: snapshot, key: key),
                  !entry.isFunctionEntry else { return nil }
            return address
        }
        func isAutoNamed(_ function: FunctionSummary) -> Bool {
            function.name.isEmpty || function.name == "sub_\(function.startAddress.hexAddress)"
        }
        func untouched(_ function: FunctionSummary) -> Bool {
            snapshot.addressOverrides[ImageAddress(slot: slot, address: function.startAddress)] == nil
                && snapshot.addressOverrides[ImageAddress(slot: slot, address: function.startAddress + 4)] == nil
        }
        var notes: [String] = []
        var chosen: [FunctionSummary] = []
        for address in request.include {
            guard let function = functions.first(where: { $0.startAddress == address }) else {
                notes.append("include 0x\(String(address, radix: 16)): not a function start in the primary slice; not added")
                continue
            }
            guard typeTarget(function) != nil, untouched(function),
                  NativeAddressFacts.isFunctionEntry(snapshot: snapshot, key: ImageAddress(slot: slot, address: address)) else {
                notes.append("include 0x\(String(address, radix: 16)): function \(function.name) has no usable type target; not added")
                continue
            }
            notes.append("include 0x\(String(address, radix: 16)): function \(function.name) added\(isAutoNamed(function) ? " (auto-named, forced)" : "")")
            chosen.append(function)
        }
        for function in functions where chosen.count < request.functionCount {
            guard !chosen.contains(where: { $0.startAddress == function.startAddress }),
                  !isAutoNamed(function), typeTarget(function) != nil, untouched(function),
                  NativeAddressFacts.isFunctionEntry(snapshot: snapshot, key: ImageAddress(slot: slot, address: function.startAddress))
            else { continue }
            chosen.append(function)
        }
        guard chosen.count == request.functionCount else {
            throw Failure("plan-found-\(chosen.count)-of-\(request.functionCount)-eligible-functions")
        }
        chosen.sort { $0.startAddress < $1.startAddress }
        var entries: [Plan.Entry] = []
        for (index, function) in chosen.enumerated() {
            let typeAddress = function.startAddress + 4
            entries.append(Plan.Entry(
                index: index, name: function.name, address: function.startAddress,
                addressHex: "0x" + String(function.startAddress, radix: 16),
                typeAddress: typeAddress, typeAddressHex: "0x" + String(typeAddress, radix: 16),
                typeName: "VAGType\(index)", signature: try signatureText(index)))
        }
        let plan = Plan(schema: 1, binary: request.binary.path, slotRaw: slot.rawValue, rule: selectionRule,
                        notes: notes, functions: entries)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try encoder.encode(plan).write(to: request.output.appendingPathComponent("functions.json"), options: .atomic)
        let elapsed = String(describing: started.duration(to: .now))
        let result = ScriptValue.object([
            "action": .string("plan"), "pid": .int(Int64(ProcessInfo.processInfo.processIdentifier)),
            "executable": .string(Bundle.main.executableURL?.path ?? "unknown"),
            "binary": .string(request.binary.path), "functionsInSlice": .int(Int64(functions.count)),
            "selected": .int(Int64(entries.count)), "notes": .array(notes.map(ScriptValue.string)),
            "elapsed": .string(elapsed)])
        try result.jsonData().write(to: request.output.appendingPathComponent("result.json"), options: .atomic)
        return ("verified-commit-batch plan functions=\(functions.count) selected=\(entries.count) elapsed=\(elapsed)", true)
    }

    private static func signature(_ index: Int) -> FunctionSignatureOverride {
        FunctionSignatureOverride(returnType: "int", args: [
            ArgOverride(rowToken: "vag-\(index)-0", name: "vagArg\(index)a", type: "char *"),
            ArgOverride(rowToken: "vag-\(index)-1", name: "vagArg\(index)b", type: "size_t")
        ])
    }

    private static func signatureText(_ index: Int) throws -> String {
        try VerifiedFieldCodec.canonicalSignature(signature(index))
    }

    // MARK: commit

    private struct OperationRecord {
        let kind: String
        let index: Int
        let name: String
        let address: UInt64
        let operationID: UUID
        let requested: String
        let outcome: String
        let committed: Bool
        let elapsed: String

        var value: ScriptValue {
            .object(["kind": .string(kind), "index": .int(Int64(index)), "function": .string(name),
                     "address": .string("0x" + String(address, radix: 16)),
                     "operationID": .string(operationID.uuidString), "requested": .string(requested),
                     "outcome": .string(outcome), "committed": .bool(committed), "elapsed": .string(elapsed)])
        }
    }

    private static func describe(_ outcome: VerifiedAnnotationCommitOutcome) -> String {
        switch outcome {
        case .committed(_, let info):
            return "committed(annotationInstalled: \(info.annotationInstalled), liveAdvanced: \(info.liveAdvanced), journalDegraded: \(info.journalDegraded))"
        case .existing: return "existing"
        case .refused(let refusal): return "refused(\(refusal.code.rawValue), \(refusal.detail ?? "-"))"
        case .indeterminate(let value): return "indeterminate(\(value.code.rawValue), \(value.detail ?? "-"))"
        }
    }

    private static func request(
        _ store: WorkspaceStore, key: ImageAddress, fieldClass: VerifiedFieldClass, value: String
    ) throws -> VerifiedAnnotationCommitRequest {
        let accepts = UInt64(store.verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count)
        func stamp(_ overrides: [ImageAddress: AddressOverride], _ revision: UInt64) -> VAProjectionStamp {
            VAProjectionStamp(workspaceID: store.workspaceID, documentID: store.documentID,
                              installationID: store.documentInstallationID, revision: revision,
                              digest: NativeAnnotationProjector.digest(overrides))
        }
        let before = stamp(store.snapshot.addressOverrides, accepts)
        var candidate = store.snapshot.addressOverrides
        var target = candidate[key] ?? AddressOverride()
        fieldClass.set(value, in: &target)
        candidate[key] = target.isEmpty ? nil : target
        let after = stamp(candidate, accepts + 1)
        let evidenceID = UUID()
        let mutation = VAMutationRequest(
            id: UUID(), base: before,
            edits: [VAEditIntent(target: VATargetReference(componentID: UUID(), function: VAAddress64(key.address)),
                                 kind: fieldClass.editKind, value: value, evidenceIDs: [evidenceID])],
            rationale: "VA-G fresh-process acceptance (harness-built receipt)")
        let receipt = try VAVerificationReceipt(
            request: mutation, decision: .accepted, before: before, after: after,
            mechanical: .candidateReadbackVerified, persistence: .pendingFreshProcessCheckpoint)
        let projection = VAWorkspaceProjection(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, revision: accepts, components: [])
        return VerifiedAnnotationCommitRequest(
            state: VAVerificationState(projection: projection, receipts: [receipt]), receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))],
            target: key, fieldClass: fieldClass, requested: value,
            expectingVersion: store.verifiedCommitVersionToken(), projector: NativeAnnotationProjector())
    }

    private struct LiveDump: Equatable {
        let overridesDigest: String
        let envelopeSHA256: String
        let dirty: Bool
        let generation: UInt64
        let installation: UUID
        var value: ScriptValue {
            .object(["overridesDigest": .string(overridesDigest), "envelopeSHA256": .string(envelopeSHA256),
                     "dirty": .bool(dirty), "mutationGeneration": .int(Int64(generation)),
                     "installationID": .string(installation.uuidString)])
        }
    }

    private static func liveDump(_ store: WorkspaceStore) -> LiveDump {
        let envelope = (try? VerifiedAnnotationAuditCodec.encode(store.verifiedAnnotationAudit)) ?? Data()
        return LiveDump(
            overridesDigest: NativeAnnotationProjector.digest(store.snapshot.addressOverrides),
            envelopeSHA256: VerifiedAnnotationAuditCodec.sha256Hex(envelope), dirty: store.hasUnsavedChanges,
            generation: store.mutationGeneration.rawValue, installation: store.documentInstallationID)
    }

    private struct DiskDump: Equatable {
        let overridesDigest: String
        let operationIDs: [UUID]
        let envelopeSHA256: String
        var value: ScriptValue {
            .object(["overridesDigest": .string(overridesDigest),
                     "operationIDs": .array(operationIDs.map { .string($0.uuidString) }),
                     "envelopeSHA256": .string(envelopeSHA256)])
        }
    }

    private static func diskDump(_ package: URL) async throws -> DiskDump {
        let location = try WorkspaceDocumentLocation.canonicalized(from: package)
        let validated = try await WorkspaceDocumentReader().readValidated(from: location)
        let contents = try MacScopeDocumentPackage.validatedContents(
            manifestData: validated.manifestData, attachmentsByBinaryID: validated.attachmentsByBinaryID,
            reconstructionState: validated.reconstructionState,
            instructionSidecarData: validated.instructionSidecarData)
        let envelope = contents.manifest.verifiedAnnotationAudit
        let bytes = envelope.flatMap { try? VerifiedAnnotationAuditCodec.encode($0) } ?? Data()
        return DiskDump(overridesDigest: NativeAnnotationProjector.digest(contents.snapshot.addressOverrides),
                        operationIDs: envelope?.records.map(\.operationID) ?? [],
                        envelopeSHA256: VerifiedAnnotationAuditCodec.sha256Hex(bytes))
    }

    private static func runCommit(_ request: Request) async throws -> (summary: String, passed: Bool) {
        guard let planURL = request.plan else { throw Failure("invalid-verified-commit-batch-plan") }
        let plan = try JSONDecoder().decode(Plan.self, from: try Data(contentsOf: planURL))
        guard plan.schema == 1, !plan.functions.isEmpty else { throw Failure("plan-schema") }
        let started = ContinuousClock.now
        let store = try await boundStore(request.binary)
        let slot = store.snapshot.primarySlot
        guard slot.rawValue == plan.slotRaw else { throw Failure("plan-slot-mismatch") }
        // The plan must still describe this analysis: same names at the same function entries.
        for entry in plan.functions {
            let key = ImageAddress(slot: slot, address: entry.address)
            guard NativeAddressFacts.isFunctionEntry(snapshot: store.snapshot, key: key),
                  store.snapshot.analysis(in: slot)?.functions.contains(where: {
                      $0.startAddress == entry.address && $0.name == entry.name }) == true,
                  store.snapshot.addressOverrides[key] == nil,
                  store.snapshot.addressOverrides[ImageAddress(slot: slot, address: entry.typeAddress)] == nil else {
                throw Failure("plan-does-not-match-analysis-at-\(entry.addressHex)")
            }
        }
        let analysisElapsed = String(describing: started.duration(to: .now))

        let reservations = BatchReservations()
        let session = WorkspaceDocumentSession(
            sessionID: WorkspaceDocumentSessionID(rawValue: UUID()), windowID: WorkspaceWindowID.fresh(),
            source: store, io: WorkspaceDocumentIO(), reservations: reservations)
        store.bindDocumentSessionMutationObserver(session)
        defer { session.close() }
        let packageName = request.binary.deletingPathExtension().lastPathComponent
            .replacingOccurrences(of: " ", with: "-") + ".mscope"
        let package = request.output.appendingPathComponent(packageName, isDirectory: true)
        let pid = ProcessInfo.processInfo.processIdentifier
        var installations: [UUID] = []
        func noteInstallation() {
            if !installations.contains(store.documentInstallationID) { installations.append(store.documentInstallationID) }
        }
        var report: [String: ScriptValue] = [
            "action": .string("commit"), "pid": .int(Int64(pid)),
            "executable": .string(Bundle.main.executableURL?.path ?? "unknown"),
            "binary": .string(request.binary.path), "package": .string(package.path),
            "plan": .string(planURL.path), "analysisElapsed": .string(analysisElapsed),
            "workspaceID": .string(store.workspaceID.uuidString), "documentID": .string(store.documentID.uuidString)
        ]
        func finish(_ passed: Bool, error: String? = nil) throws -> (summary: String, passed: Bool) {
            noteInstallation()
            report["passed"] = .bool(passed)
            report["error"] = error.map(ScriptValue.string) ?? .null
            report["writerInstallationIDs"] = .array(installations.map { .string($0.uuidString) })
            report["elapsed"] = .string(String(describing: started.duration(to: .now)))
            try ScriptValue.object(report).jsonData().write(
                to: request.output.appendingPathComponent("result.json"), options: .atomic)
            return ("verified-commit-batch commit passed=\(passed) error=\(error ?? "none") elapsed=\(String(describing: started.duration(to: .now)))", passed)
        }

        noteInstallation()
        let saved = await session.saveAs(to: package)
        guard case .saved(clean: true, adopted: _) = saved else {
            report["saveAs"] = .string(String(describing: saved))
            return try finish(false, error: "saveAs-failed")
        }
        noteInstallation()
        progress("first-save-done")
        for entry in plan.functions {
            store.upsertTypeDefinition(TypeDefinition(kind: .struct, name: entry.typeName))
        }
        let baselineSave = await session.save()
        guard case .saved(clean: true, adopted: _) = baselineSave else {
            report["baselineSave"] = .string(String(describing: baselineSave))
            return try finish(false, error: "baseline-save-failed")
        }
        progress("baseline-save-done")

        if request.injectReadbackMismatch {
            let injected = try await injectedFailure(plan: plan, store: store, session: session, package: package)
            report["injection"] = injected.injection
            return try finish(injected.passed, error: injected.passed ? nil : "injection-not-as-expected")
        }

        var records: [OperationRecord] = []
        var operations: [VerifiedCheckpointExpectation.Operation] = []
        var firstFailure: String?
        func commit(kind: String, entry: Plan.Entry, key: ImageAddress, fieldClass: VerifiedFieldClass,
                    value: String) async throws {
            let verified = try Self.request(store, key: key, fieldClass: fieldClass, value: value)
            noteInstallation()
            let begin = ContinuousClock.now
            let outcome = await session.commitVerifiedAnnotation(verified)
            let committed: Bool
            if case .committed = outcome { committed = true } else { committed = false }
            Self.progress("commit \(kind) \(entry.index) \(describe(outcome)) \(begin.duration(to: .now))")
            records.append(OperationRecord(
                kind: kind, index: entry.index, name: entry.name, address: key.address,
                operationID: verified.operationID, requested: value, outcome: describe(outcome),
                committed: committed, elapsed: String(describing: begin.duration(to: .now))))
            guard committed else {
                firstFailure = firstFailure ?? "\(kind)-\(entry.index)-\(describe(outcome))"
                return
            }
            let beforeRevision = verified.receipt.before.revision
            if fieldClass == .addressType {
                operations.append(.addressType(
                    operationID: verified.operationID, requestDigest: verified.receipt.requestDigest,
                    decision: .accepted, slot: key.slot.rawValue, address: key.address, requested: value,
                    baseline: nil, beforeRevision: beforeRevision, afterRevision: beforeRevision + 1))
            } else {
                operations.append(.functionSignature(
                    operationID: verified.operationID, requestDigest: verified.receipt.requestDigest,
                    decision: .accepted, slot: key.slot.rawValue, address: key.address, requested: value,
                    baseline: nil, beforeRevision: beforeRevision, afterRevision: beforeRevision + 1))
            }
        }
        // 10 type edits, then 10 signature edits; the first non-committed outcome stops the run.
        for entry in plan.functions where firstFailure == nil {
            try await commit(kind: "type", entry: entry, key: ImageAddress(slot: slot, address: entry.typeAddress),
                             fieldClass: .addressType, value: entry.typeName)
        }
        for entry in plan.functions where firstFailure == nil {
            try await commit(kind: "signature", entry: entry, key: ImageAddress(slot: slot, address: entry.address),
                             fieldClass: .functionSignature, value: entry.signature)
        }
        let finalSave = await session.save()
        report["finalSave"] = .string(String(describing: finalSave))
        report["operations"] = .array(records.map(\.value))
        report["committedCount"] = .int(Int64(records.filter(\.committed).count))
        report["typeCommitted"] = .int(Int64(records.filter { $0.kind == "type" && $0.committed }.count))
        report["signatureCommitted"] = .int(Int64(records.filter { $0.kind == "signature" && $0.committed }.count))
        report["live"] = liveDump(store).value
        // The expectation covers every operation that committed, so a partial run is still judged honestly.
        if !operations.isEmpty {
            let expectation = VerifiedCheckpointExpectation(
                schemaVersion: VerifiedCheckpointExpectation.requiredSchemaVersion(for: operations),
                workspaceID: store.workspaceID, documentID: store.documentID,
                writerInstallationIDs: installations, writerProcessID: pid, operations: operations)
            let path = request.output.appendingPathComponent("expectation.json")
            try expectation.encoded().write(to: path, options: .atomic)
            report["expectation"] = .string(path.path)
        }
        if let firstFailure { return try finish(false, error: firstFailure) }
        guard case .saved(clean: true, adopted: _) = finalSave else { return try finish(false, error: "final-save-not-clean") }
        return try finish(true)
    }

    // MARK: T14

    private static func injectedFailure(
        plan: Plan, store: WorkspaceStore, session: WorkspaceDocumentSession, package: URL
    ) async throws -> (injection: ScriptValue, passed: Bool) {
        guard let entry = plan.functions.first else { throw Failure("plan-empty") }
        let key = ImageAddress(slot: store.snapshot.primarySlot, address: entry.typeAddress)
        let liveBefore = liveDump(store)
        let diskBefore = try await diskDump(package)
        let verified = try Self.request(store, key: key, fieldClass: .addressType, value: entry.typeName)
        // The existing DEBUG seam: corrupt the snapshot the published-readback leg reads back.
        session.verifiedCommitTestHooks.mutateReadbackSnapshot = { snapshot in
            snapshot.addressOverrides[key]?.appliedTypeName = "VAGTampered"
        }
        let outcome = await session.commitVerifiedAnnotation(verified)
        session.verifiedCommitTestHooks.mutateReadbackSnapshot = nil
        let liveAfter = liveDump(store)
        let diskAfter = try await diskDump(package)
        var code = "none", stage = "none"
        switch outcome {
        case .indeterminate(let value): code = value.code.rawValue; stage = value.detail ?? "none"
        case .refused(let value): code = value.code.rawValue; stage = value.detail ?? "none"
        default: break
        }
        let latched = store.verifiedCommitLatch
        let injection = ScriptValue.object([
            "mechanism": .string("session.verifiedCommitTestHooks.mutateReadbackSnapshot (DEBUG): appliedTypeName at the type target read back as VAGTampered"),
            "operationID": .string(verified.operationID.uuidString), "target": .string(entry.typeAddressHex),
            "requested": .string(entry.typeName), "outcome": .string(describe(outcome)),
            "typedCode": .string(code), "stage": .string(stage),
            "latch": latched.map { .string($0.reason) } ?? .null,
            "liveBefore": liveBefore.value, "liveAfter": liveAfter.value,
            "liveUnchanged": .bool(liveBefore == liveAfter),
            "diskBefore": diskBefore.value, "diskAfter": diskAfter.value,
            "diskUnchanged": .bool(diskBefore == diskAfter),
            "diskContainsOperation": .bool(diskAfter.operationIDs.contains(verified.operationID))
        ])
        let isReadbackStage = stage.hasPrefix("content")
        let passed = liveBefore == liveAfter && code == "publishedReadbackFailed" && isReadbackStage
            && diskAfter.operationIDs.contains(verified.operationID)
        return (injection, passed)
    }

    // MARK: Collaborators

    private struct QuietRecents: WorkspaceRecentsRecording {
        func noteRecentDocument(_ url: URL) {}
        var recentDocumentURLs: [URL] { [] }
        func clearRecentDocuments() {}
    }

    /// Single-process reservation table (no other windows exist in this mode).
    private final class BatchReservations: WorkspaceDocumentLocationReserving {
        private struct Owner { let sessionID: WorkspaceDocumentSessionID; let windowID: WorkspaceWindowID }
        private var owners: [URL: Owner] = [:]
        private var publications: [WorkspaceDocumentPublicationReservation: (Owner, Bool)] = [:]

        func owner(of location: WorkspaceDocumentLocation) -> WorkspaceWindowID? {
            owners[location.canonicalURL]?.windowID
        }
        func reserve(_ location: WorkspaceDocumentLocation, for sessionID: WorkspaceDocumentSessionID,
                     windowID: WorkspaceWindowID) -> WorkspaceDocumentLocationReservationResult {
            if let existing = owners[location.canonicalURL], existing.sessionID != sessionID {
                return .alreadyOwned(existing.windowID)
            }
            owners[location.canonicalURL] = Owner(sessionID: sessionID, windowID: windowID)
            return .reserved
        }
        func release(_ location: WorkspaceDocumentLocation, for sessionID: WorkspaceDocumentSessionID) {
            if owners[location.canonicalURL]?.sessionID == sessionID { owners[location.canonicalURL] = nil }
        }
        func releaseAll(for sessionID: WorkspaceDocumentSessionID) {
            owners = owners.filter { $0.value.sessionID != sessionID }
        }
        func beginPhysicalPublication(
            _ staged: WorkspaceDocumentStagedPackage, to destination: WorkspaceDocumentLocation,
            retainingPublishedOwnership: Bool, for sessionID: WorkspaceDocumentSessionID, windowID: WorkspaceWindowID
        ) -> WorkspaceDocumentPublicationReservationResult {
            if let existing = owners[destination.canonicalURL], existing.windowID != windowID {
                return .alreadyOwned(existing.windowID)
            }
            let publication = WorkspaceDocumentPublicationReservation()
            publications[publication] = (Owner(sessionID: sessionID, windowID: windowID), retainingPublishedOwnership)
            return .reserved(publication)
        }
        func completePhysicalPublication(
            _ publication: WorkspaceDocumentPublicationReservation, at publishedLocation: WorkspaceDocumentLocation
        ) -> WorkspaceDocumentPublicationCompletionResult {
            guard let (owner, retaining) = publications.removeValue(forKey: publication) else { return .invalid }
            if retaining {
                guard case .reserved = reserve(publishedLocation, for: owner.sessionID, windowID: owner.windowID) else {
                    return .invalid
                }
            }
            return .completed
        }
        func cancelPhysicalPublication(_ publication: WorkspaceDocumentPublicationReservation) {
            publications[publication] = nil
        }
    }
}
#endif
