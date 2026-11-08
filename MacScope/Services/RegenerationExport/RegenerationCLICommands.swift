import Foundation
import Darwin

/// Exports through the live captured-workspace scripting bridge. Legacy CLI admission
/// recognizes the command only to refuse it before loading; general MCP remains closed.
enum RegenerationCLICommands {
    static let command = ScriptingCommandInfo(name: "export-project",
        summary: "Export the captured macOS arm64 application's buildable stub project and supported editable resources into a NEW absolute outputDirectory. Requires appPath; optional image selects a loaded image. Optional cBodiesPath imports exactly identity-bound, signature-assisted C bodies as filled (not compilation or acceptance evidence); other functions remain stubs. Unsupported resources retain originals.",
        mutates: false, arguments: ["appPath", "outputDirectory", "image", "cBodiesPath"])

    @MainActor
    static func scriptSteps(from script: ScriptValue) throws -> [HeadlessAutomationAuthority.ScriptStep] {
        guard case .array(let values) = script, values.count <= HeadlessAutomationAuthority.maximumScriptSteps else {
            throw HeadlessAutomationAuthorityError.invalidScript
        }
        return try values.flatMap { value -> [HeadlessAutomationAuthority.ScriptStep] in
            guard case .object(let fields) = value, fields["command"]?.stringValue == command.name else {
                return try HeadlessAutomationAuthority.scriptSteps(from: .array([value]))
            }
            guard Set(fields.keys).isSubset(of: ["command", "arguments"]), let arguments = fields["arguments"] else {
                throw HeadlessAutomationAuthorityError.invalidArguments
            }
            try validate(arguments)
            return [.init(command: command.name, arguments: arguments)]
        }
    }

    static func validate(_ arguments: ScriptValue) throws {
        guard case .object(let fields) = arguments,
              Set(fields.keys).isSubset(of: Set(command.arguments)) else { throw HeadlessAutomationAuthorityError.invalidArguments }
        for name in ["appPath", "outputDirectory"] {
            guard let value = fields[name]?.stringValue, !value.isEmpty, value.utf8.count <= 4_096,
                  value.hasPrefix("/"), !value.contains("\0"), !value.split(separator: "/").contains("..") else {
                throw ScriptingError.invalidArgument(name + " must be an absolute bounded path without parent traversal")
            }
        }
        guard let appPath = fields["appPath"]?.stringValue,
              URL(fileURLWithPath: appPath).pathExtension.lowercased() == "app" else {
            throw ScriptingError.invalidArgument("appPath must name an application bundle")
        }
        if let path = fields["cBodiesPath"] {
            guard let value = path.stringValue, value.hasPrefix("/"), value.utf8.count <= 4096,
                  !value.contains("\0"), !value.split(separator: "/").contains("..") else {
                throw ScriptingError.invalidArgument("cBodiesPath must be an absolute bounded path")
            }
        }
        if let image = fields["image"], image != .null {
            switch image {
            case .int(let value) where value >= 0 && value <= Int64(Int32.max): break
            case .string(let value) where !value.isEmpty && value.utf8.count <= 64: break
            default: throw ScriptingError.invalidArgument("image must be an existing slot number or image-owner UUID")
            }
        }
    }

    @MainActor
    static func execute(arguments: ScriptValue, store: WorkspaceStore, maximumDuration: TimeInterval,
                        beforePublish: () throws -> Void) throws -> ScriptValue {
        try validate(arguments)
        guard maximumDuration.isFinite, maximumDuration > 0, maximumDuration <= 30 else {
            throw RegenerationError.invalidInput("export duration must be within 30 seconds")
        }
        let budget = try RegenerationWorkBudget.start(durationNanoseconds: UInt64(maximumDuration * 1_000_000_000))
        try budget.checkpoint()
        // Convert the one budget's remaining duration for resource tools; do not reset it.
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < budget.deadlineUptimeNanoseconds else { throw RegenerationWorkBudgetError.deadlineExceeded }
        let remaining = Double(budget.deadlineUptimeNanoseconds - now) / 1_000_000_000
        let deadline = ProcessInfo.processInfo.systemUptime + remaining
        guard let appPath = arguments["appPath"]?.stringValue,
              let outputPath = arguments["outputDirectory"]?.stringValue else { throw HeadlessAutomationAuthorityError.invalidArguments }
        let destination = URL(fileURLWithPath: outputPath)
        guard !FileManager.default.fileExists(atPath: destination.path) else { throw RegenerationError.destinationExists }
        let snapshot = store.snapshot
        let slot = try WorkspaceScriptingAPI.resolveImageSlot(arguments, snapshot: snapshot)
        guard let binary = snapshot.binary(in: slot) else { throw RegenerationError.invalidInput("selected image is absent") }
        let executable = URL(fileURLWithPath: binary.resolvedExecutablePath ?? binary.path).resolvingSymlinksInPath()
        let application = try RegenerationAppCapture.capture(app: URL(fileURLWithPath: appPath).resolvingSymlinksInPath(), capturedExecutable: executable)
        var input = try RegenerationSnapshotAdapter.prepare(snapshot: snapshot, slot: slot, application: application)
        var remainingInputBytes = budget.maximumInputBytes
        func chargeInput(_ count: Int) throws {
            guard count >= 0, count <= remainingInputBytes else { throw RegenerationWorkBudgetError.inputLimitExceeded }
            remainingInputBytes -= count
        }
        try chargeInput(snapshot.analysis(in: slot)?.imageBytes.count ?? 0)
        try chargeInput(application.originalInfoPlist.count)
        for bytes in application.resources.values {
            try budget.checkpoint()
            try chargeInput(bytes.count)
        }
        let table = try dependencyTable(budget: budget, maximumBytes: min(262_144, remainingInputBytes))
        let inventory = try RegenerationDependencyInventory.prepare(snapshot: snapshot, slot: slot,
            app: URL(fileURLWithPath: appPath).resolvingSymlinksInPath(), table: table, budget: budget)
        input.diagnostics.append(contentsOf: inventory.diagnostics)
        let work = destination.deletingLastPathComponent().appendingPathComponent(".regeneration-work-" + UUID().uuidString.lowercased())
        // Open the parent without symlink traversal before creating any work or output.
        let parent = try RegenerationFileSystem.openOrdinaryDirectory(destination.deletingLastPathComponent())
        close(parent)
        var runner = RegenerationToolRunner()
        try runner.checkStorage(at: destination.deletingLastPathComponent())
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: false)
        runner.logRoot = work
        let resource = try RegenerationResourcePipeline().prepare(originals: application.resources,
            sourceLanguage: application.sourceLanguage, workDirectory: work, deadline: deadline, runner: runner)
        try budget.checkpoint()
        var project = try RegenerationProjectRenderer.render(input, resources: resource.records,
            dependencyFiles: inventory.files,
            dependencyCapability: .init(path: inventory.path, coverage: inventory.coverage,
                liveBundleObservations: inventory.liveBundleObservations))
        for (path, data) in resource.files {
            guard project.files[path] == nil else { throw RegenerationError.invalidInput("resource/report output collision") }
            project.files[path] = data
        }
        if let path = arguments["cBodiesPath"]?.stringValue {
            let bytes = try readOrdinaryFile(URL(fileURLWithPath: path), budget: budget,
                maximumBytes: min(8_388_608, remainingInputBytes))
            try chargeInput(bytes.count)
            let packet = try JSONDecoder().decode(RegenerationCBodyPacket.self, from: bytes)
            try RegenerationCStubFill.apply(packet, to: &project)
            try budget.checkpoint()
        }
        let xcodegen = try RegenerationXcodeGenTool.locate()
        try RegenerationExportService().publish(project, to: destination) { stage in
            runner.timeout = min(30, max(0.001, deadline - ProcessInfo.processInfo.systemUptime))
            try runner.run(executable: xcodegen, arguments: ["generate"], workingDirectory: stage).requireSuccess()
            try budget.checkpoint()
            try beforePublish()
            try budget.checkpoint()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RegenerationError.toolFailed("export deadline before publication") }
        }
        return .object(["ok": .bool(true), "project": .string(destination.appendingPathComponent(RegenerationEncoding.identifier(input.applicationName) + ".xcodeproj").path),
            "manifest": .string(destination.appendingPathComponent("REGEN-MANIFEST.json").path), "workDirectory": .string(work.path),
            "functionCount": .int(Int64(project.manifest.functions.count)), "stubCount": .int(Int64(project.manifest.functions.filter { $0.state == .stub }.count)),
            "filledCount": .int(Int64(project.manifest.functions.filter { $0.state == .filled }.count)),
            "resourceCount": .int(Int64(resource.records.count)),
            "dependencyCount": .int(Int64(inventory.dependencyCount)),
            "convertedResourceCount": .int(Int64(resource.records.filter(\.selectsSource).count)),
            "diagnostics": .array((project.manifest.diagnostics + resource.records.flatMap(\.diagnostics)).map(ScriptValue.string))])
    }
    private static func dependencyTable(budget: RegenerationWorkBudget, maximumBytes: Int) throws -> KnownDependencyTable {
        try budget.checkpoint()
        guard maximumBytes > 0, maximumBytes <= 262_144,
              let url = Bundle.main.url(forResource: "KnownDependencies", withExtension: "json") else {
            throw RegenerationError.invalidInput("packaged dependency mapping is unavailable or exceeds the shared input budget")
        }
        let data = try readOrdinaryFile(url, budget: budget, maximumBytes: maximumBytes)
        let table = try JSONDecoder().decode(KnownDependencyTable.self, from: data)
        try budget.checkpoint()
        return table
    }

    static func readOrdinaryFile(_ url: URL, budget: RegenerationWorkBudget,
                                         maximumBytes: Int) throws -> Data {
        guard maximumBytes > 0 else { throw RegenerationWorkBudgetError.inputLimitExceeded }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw RegenerationError.invalidInput("cannot open ordinary dependency mapping") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_size > 0, before.st_size <= maximumBytes else {
            throw RegenerationError.invalidInput("dependency mapping is not an ordinary bounded file")
        }
        var data = Data()
        while true {
            try budget.checkpoint()
            let part = try handle.read(upToCount: min(65_536, maximumBytes - data.count + 1)) ?? Data()
            if part.isEmpty { break }
            guard part.count <= maximumBytes - data.count else { throw RegenerationWorkBudgetError.inputLimitExceeded }
            data.append(part)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size, data.count == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw RegenerationError.invalidInput("dependency mapping changed during read")
        }
        try budget.checkpoint()
        return data
    }
}

extension WorkspaceScriptingAPI {
    /// Existing live AppleScript dispatch already owns an analyzed workspace. Headless MCP's
    /// separate closed allowlist still excludes this filesystem-writing command.
    nonisolated static var regenerationCommands: [DocumentCommand] {
        [(RegenerationCLICommands.command, { arguments, store in
            try RegenerationCLICommands.execute(arguments: arguments, store: store,
                maximumDuration: 30, beforePublish: {})
        })]
    }
}
