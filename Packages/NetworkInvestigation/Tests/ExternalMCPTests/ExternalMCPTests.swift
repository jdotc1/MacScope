import Foundation
import Testing
@testable import ExternalMCP
import Darwin

@Suite(.serialized)
struct ExternalMCPTests {
    private func fixtureURL() throws -> URL {
        var directory = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = directory.appendingPathComponent("MCPFixtureServer").resolvingSymlinksInPath()
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
            directory.deleteLastPathComponent()
        }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let candidate = root.appendingPathComponent(".build/arm64-apple-macosx/debug/MCPFixtureServer").resolvingSymlinksInPath()
        if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        let products = root.appendingPathComponent(".build/out/Products/Debug/MCPFixtureServer").resolvingSymlinksInPath()
        if FileManager.default.isExecutableFile(atPath: products.path) { return products }
        throw MCPClientError.invalidConfiguration
    }

    private func configuration(_ mode: String = "normal", limits: MCPResourceLimits = .init(),
                               extraArguments: [String] = []) async throws -> MCPConnectionConfiguration {
        let url = try fixtureURL()
        return MCPConnectionConfiguration(executableURL: url, expectedExecutableSHA256: try await MCPExecutableValidation.sha256(at: url),
                                          arguments: [mode] + extraArguments, limits: limits)
    }

    private func withFixture(_ mode: String = "normal", limits: MCPResourceLimits = .init(),
                             extraArguments: [String] = [],
                             _ body: @Sendable (SDKExternalMCPClient) async throws -> Void) async throws {
        let client = SDKExternalMCPClient()
        do {
            _ = try await client.connect(configuration: configuration(mode, limits: limits, extraArguments: extraArguments))
            _ = try await client.discoverTools()
            try await body(client)
            await client.disconnect()
        } catch {
            await client.disconnect()
            throw error
        }
    }

    @Test func nativeChildNegotiatesAndPreservesStructuredResults() async throws {
        try await withFixture { client in
            let snapshot = await client.snapshot()
            #expect(snapshot.state == .connected)
            #expect(snapshot.protocolVersion == "2025-11-25")
            #expect(snapshot.connectionID != nil)
            let tools = try await client.discoverTools()
            #expect(tools.count == 5)
            #expect(tools.allSatisfy { $0.schemaDigest.count == 64 })
            #expect(await client.snapshot().toolCatalogRevision == snapshot.toolCatalogRevision)
            let output = try await client.invoke(tool: "echo", arguments: .object(["number": .int(42)]))
            #expect(output.structuredContent?.objectValue?["number"] == .int(42))
            #expect(output.textContent == ["echo"])
            #expect(output.connectionID == snapshot.connectionID)
        }
    }

    @Test func paginationAndCursorLoopAreBounded() async throws {
        try await withFixture("paged") { client in
            let tools = try await client.discoverTools()
            #expect(tools.count == 5)
        }
        let client = SDKExternalMCPClient()
        do {
            _ = try await client.connect(configuration: configuration("loop_cursor"))
            await #expect(throws: MCPClientError.repeatedCursor) { try await client.discoverTools() }
            await client.disconnect()
        } catch {
            await client.disconnect()
            throw error
        }
    }

    @Test func unsupportedProtocolAndMissingCapabilitiesFailClosed() async throws {
        for (mode, expected) in [("unsupported", MCPClientError.unsupportedProtocol), ("no_tools", .capabilityMissing)] {
            let client = SDKExternalMCPClient()
            do {
                let config = try await configuration(mode)
                await #expect(throws: expected) { try await client.connect(configuration: config) }
                #expect(await client.snapshot().connectionID == nil)
                await client.disconnect()
            } catch {
                await client.disconnect()
                throw error
            }
        }
    }

    @Test func unknownToolsAndInvalidArgumentsNeverReachVendor() async throws {
        try await withFixture { client in
            await #expect(throws: MCPClientError.unknownTool) {
                try await client.invoke(tool: "clear_session", arguments: .object([:]))
            }
            await #expect(throws: MCPClientError.invalidArguments) { try await client.invoke(tool: "echo", arguments: .string("shell command")) }
            await #expect(throws: MCPClientError.unsupportedContent) {
                try await client.invoke(tool: "echo", arguments: .object(["data": .data(Data([1, 2, 3]))]))
            }
            #expect(await client.snapshot().state == .connected)
        }
    }

    @Test func serverToolErrorRemainsExplicit() async throws {
        try await withFixture { client in
            let result = try await client.invoke(tool: "fail", arguments: .object([:]))
            #expect(result.isError)
            #expect(await client.snapshot().diagnosticCode == nil)
        }
    }

    @Test func concurrentRequestsMatchOutOfOrderResponses() async throws {
        try await withFixture("out_of_order") { client in
            try await withThrowingTaskGroup(of: Int.self) { group in
                for value in 0..<4 {
                    group.addTask {
                        let result = try await client.invoke(tool: "echo", arguments: .object(["sequence": .int(value)]))
                        #expect(result.structuredContent?.objectValue?["sequence"] == .int(value))
                        return value
                    }
                }
                var values = Set<Int>()
                for try await value in group { values.insert(value) }
                #expect(values == Set(0..<4))
            }
        }
    }

    @Test func partialFramesAndDuplicateUnknownIdentifiers() async throws {
        for mode in ["partial", "duplicate"] {
            try await withFixture(mode) { client in
                for value in 0..<3 {
                    let output = try await client.invoke(tool: "echo", arguments: .object(["value": .int(value)]))
                    #expect(output.structuredContent?.objectValue?["value"] == .int(value))
                }
            }
        }
    }

    @Test func deadlineReleasesPendingAndInvalidatesGeneration() async throws {
        try await withFixture(limits: .init(requestTimeout: 0.5)) { client in
            await #expect(throws: MCPClientError.deadlineExceeded) { try await client.invoke(tool: "wait", arguments: .object([:])) }
            let snapshot = await client.snapshot()
            #expect(snapshot.connectionID == nil)
            #expect(snapshot.diagnosticCode == MCPClientError.deadlineExceeded.rawValue)
        }
    }

    @Test func cancellationFailsSharedPendingWorkWithoutReplay() async throws {
        try await withFixture { client in
            let first = Task { try await client.invoke(tool: "wait", arguments: .object([:])) }
            let second = Task { try await client.invoke(tool: "wait", arguments: .object([:])) }
            try await Task.sleep(for: .milliseconds(50))
            first.cancel()
            await #expect(throws: MCPClientError.cancelled) { try await first.value }
            await #expect(throws: MCPClientError.cancelled) { try await second.value }
            #expect(await client.snapshot().connectionID == nil)
        }
    }

    @Test func immediateCancellationDoesNotStrandSDKRegistration() async throws {
        for _ in 0..<8 {
            try await withFixture { client in
                let operation = Task { try await client.invoke(tool: "wait", arguments: .object([:])) }
                operation.cancel()
                await #expect(throws: MCPClientError.cancelled) { try await operation.value }
            }
        }
    }

    @Test func disconnectWhilePendingReleasesRequestAndOnlyOwnedChild() async throws {
        try await withFixture { client in
            let pidResult = try await client.invoke(tool: "pid", arguments: .object([:]))
            let pid = try #require(pidResult.structuredContent?.objectValue?["pid"]?.intValue)
            let operation = Task { try await client.invoke(tool: "wait", arguments: .object([:])) }
            try await Task.sleep(for: .milliseconds(30))
            await client.disconnect()
            await #expect(throws: MCPClientError.transportClosed) { try await operation.value }
            for _ in 0..<20 where kill(Int32(pid), 0) == 0 { try await Task.sleep(for: .milliseconds(25)) }
            #expect(kill(Int32(pid), 0) == -1)
            #expect(await client.snapshot().state == .disconnected)
        }
    }

    @Test func malformedOversizedDeepEOFAndCrashFailBoundedly() async throws {
        for mode in ["invalid_json", "oversize", "deep", "eof", "crash"] {
            try await withFixture(mode, limits: .init(requestTimeout: 1)) { client in
                await #expect(throws: (any Error).self) { try await client.invoke(tool: "echo", arguments: .object([:])) }
                let snapshot = await client.snapshot()
                #expect(snapshot.connectionID == nil)
                #expect(snapshot.diagnosticCode?.contains("PRIVATE_SECRET") == false)
            }
        }
    }

    @Test func unexpectedResultDoesNotBecomeSuccessfulEvidence() async throws {
        try await withFixture("bad_result", limits: .init(requestTimeout: 0.5)) { client in
            await #expect(throws: (any Error).self) { try await client.invoke(tool: "echo", arguments: .object([:])) }
        }
    }

    @Test func reconnectIssuesNewGeneration() async throws {
        let client = SDKExternalMCPClient()
        do {
            let config = try await configuration()
            let old = try await client.connect(configuration: config)
            await client.disconnect()
            let new = try await client.connect(configuration: config)
            #expect(old.connectionID != new.connectionID)
            await #expect(throws: MCPClientError.unknownTool) { try await client.invoke(tool: "echo", arguments: .object([:])) }
            _ = try await client.discoverTools()
            _ = try await client.invoke(tool: "echo", arguments: .object([:]))
            await client.disconnect()
        } catch {
            await client.disconnect()
            throw error
        }
    }

    @Test func listChangedInvalidatesCatalog() async throws {
        try await withFixture { client in
            let before = await client.snapshot().toolCatalogRevision
            let oldDigest = try await client.discoverTools().first?.schemaDigest
            do { _ = try await client.invoke(tool: "notify_change", arguments: .object([:])) } catch MCPClientError.staleConnection {}
            try await Task.sleep(for: .milliseconds(20))
            #expect(await client.snapshot().toolCatalogRevision > before)
            await #expect(throws: MCPClientError.unknownTool) { try await client.invoke(tool: "echo", arguments: .object([:])) }
            let refreshed = try await client.discoverTools()
            #expect(refreshed.count == 5)
            #expect(refreshed.first?.schemaDigest != oldDigest)
        }
    }

    @Test func invalidExecutableAndEnvironmentAreRejected() async throws {
        let good = try await configuration()
        let client = SDKExternalMCPClient()
        do {
            let badHash = MCPConnectionConfiguration(executableURL: good.executableURL, expectedExecutableSHA256: String(repeating: "0", count: 64))
            await #expect(throws: MCPClientError.untrustedExecutable) { try await client.connect(configuration: badHash) }
            let badEnv = MCPConnectionConfiguration(executableURL: good.executableURL, expectedExecutableSHA256: good.expectedExecutableSHA256,
                                                    environment: ["PROXYMAN_TOKEN": "secret"])
            await #expect(throws: MCPClientError.invalidConfiguration) { try await client.connect(configuration: badEnv) }
            await client.disconnect()
        } catch {
            await client.disconnect()
            throw error
        }
    }

    @Test func canonicalSchemasAndJSONContainment() throws {
        let a: MCPJSONValue = .object(["type": .string("object"), "required": .array([.string("id")])])
        let b: MCPJSONValue = .object(["required": .array([.string("id")]), "type": .string("object")])
        #expect(try MCPBoundaryValidation.schemaDigest(input: a, output: nil, limits: .init()) == MCPBoundaryValidation.schemaDigest(input: b, output: nil, limits: .init()))
        #expect(throws: MCPClientError.invalidArguments) { try MCPBoundaryValidation.validate(.double(.infinity), limits: .init()) }
        let decoded = try JSONDecoder().decode(MCPJSONValue.self, from: Data("\"data:text/plain;base64,c2VjcmV0\"".utf8))
        #expect(throws: MCPClientError.unsupportedContent) { try MCPBoundaryValidation.validate(decoded, limits: .init()) }
        #expect(throws: MCPClientError.malformedMessage) { try MCPBoundaryValidation.validateFrame(Data("{invalid}".utf8), limits: .init()) }
    }

    @Test func catalogAndPendingRequestLimitsFailClosed() async throws {
        for (mode, limits) in [("normal", MCPResourceLimits(maximumTools: 2)), ("paged", .init(maximumToolPages: 1))] {
            let client = SDKExternalMCPClient()
            do {
                _ = try await client.connect(configuration: configuration(mode, limits: limits))
                await #expect(throws: MCPClientError.toolCatalogLimit) { try await client.discoverTools() }
                await #expect(throws: MCPClientError.unknownTool) { try await client.invoke(tool: "echo", arguments: .object([:])) }
                await client.disconnect()
            } catch {
                await client.disconnect()
                throw error
            }
        }
        try await withFixture(limits: .init(maximumPendingRequests: 1)) { client in
            let pending = Task { try await client.invoke(tool: "wait", arguments: .object([:])) }
            try await Task.sleep(for: .milliseconds(30))
            await #expect(throws: MCPClientError.tooManyRequests) { try await client.invoke(tool: "echo", arguments: .object([:])) }
            pending.cancel()
            await #expect(throws: MCPClientError.cancelled) { try await pending.value }
        }
    }

    @Test func initializationDeadlineAndDisconnectDuringConnect() async throws {
        let client = SDKExternalMCPClient()
        do {
            let config = try await configuration("silent", limits: .init(requestTimeout: 0.5))
            await #expect(throws: MCPClientError.deadlineExceeded) { try await client.connect(configuration: config) }
            let connection = Task { try await client.connect(configuration: config) }
            try await Task.sleep(for: .milliseconds(20))
            await client.disconnect()
            await #expect(throws: (any Error).self) { try await connection.value }
            #expect(await client.snapshot().connectionID == nil)
            await client.disconnect()
        } catch {
            await client.disconnect()
            throw error
        }
    }

    @Test func transportBackpressureIsBoundedWithoutConsumer() async throws {
        let recorder = FixtureFailureRecorder()
        let transport = BoundedSubprocessTransport(configuration: try await configuration("partial", limits: .init(maximumBufferedMessages: 1))) {
            await recorder.record($0)
        }
        do {
            try await transport.connect()
            try await transport.send(Data("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}".utf8))
            try await Task.sleep(for: .milliseconds(30))
            try await transport.send(Data("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}".utf8))
            for _ in 0..<40 where await recorder.error == nil { try await Task.sleep(for: .milliseconds(5)) }
            #expect(await recorder.error == .backpressure)
            await transport.disconnect()
        } catch {
            await transport.disconnect()
            throw error
        }
    }

    @Test func releasingClientOwnerTerminatesOwnedChild() async throws {
        let config = try await configuration()
        func createAndReleaseOwner() async throws -> Int {
            let owner = SDKExternalMCPClient()
            do {
                _ = try await owner.connect(configuration: config)
                _ = try await owner.discoverTools()
                let output = try await owner.invoke(tool: "pid", arguments: .object([:]))
                return try #require(output.structuredContent?.objectValue?["pid"]?.intValue)
            } catch {
                await owner.disconnect()
                throw error
            }
        }
        let pid = try await createAndReleaseOwner()
        for _ in 0..<80 where kill(Int32(pid), 0) == 0 { try await Task.sleep(for: .milliseconds(25)) }
        #expect(kill(Int32(pid), 0) == -1)
    }

    @Test func unsolicitedServerAuthorityAndNotificationFloodsAreDenied() async throws {
        try await withFixture("incoming") { client in
            let output = try await client.invoke(tool: "echo", arguments: .object([:]))
            #expect(output.structuredContent?.objectValue?["unsolicitedRequestDenied"] == .bool(true))
        }
        try await withFixture("flood", limits: .init(maximumFramesPerSecond: 16)) { client in
            await #expect(throws: MCPClientError.backpressure) { try await client.invoke(tool: "echo", arguments: .object([:])) }
            #expect(await client.snapshot().state == .degraded)
        }
    }

    @Test func concurrentDiscoveryCoalescesAndInvocationWaitsForRefresh() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        try await withFixture("catalog_barrier", extraArguments: [directory.path]) { client in
            let revision = await client.snapshot().toolCatalogRevision
            try Data().write(to: directory.appendingPathComponent("arm"))
            let first = Task { try await client.discoverTools() }
            try await Self.waitForMarker(directory.appendingPathComponent("entered"))
            let second = Task { try await client.discoverTools() }
            let third = Task { try await client.discoverTools() }
            let invocation = Task { try await client.invoke(tool: "echo", arguments: .object([:])) }
            let release = Task {
                try await Task.sleep(for: .milliseconds(75))
                try Data().write(to: directory.appendingPathComponent("release"))
            }
            let one = try await first.value, two = try await second.value, three = try await third.value
            let result = try await invocation.value
            try await release.value
            #expect(one == two && two == three && one.count == 5)
            #expect(result.structuredContent?.objectValue?["catalogCallCount"] == .int(2))
            #expect(await client.snapshot().toolCatalogRevision == revision)
            #expect(await client.snapshot().state == .connected)
        }
    }

    @Test func cancellingCoalescedDiscoveryFailsWaitersAndAllowsFreshReconnect() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = try await configuration("catalog_barrier", extraArguments: [directory.path])
        let client = SDKExternalMCPClient()
        do {
            let original = try await client.connect(configuration: config)
            _ = try await client.discoverTools()
            try Data().write(to: directory.appendingPathComponent("arm"))
            let first = Task { try await client.discoverTools() }
            try await Self.waitForMarker(directory.appendingPathComponent("entered"))
            let cancelled = Task { try await client.discoverTools() }
            cancelled.cancel()
            await #expect(throws: MCPClientError.cancelled) { try await cancelled.value }
            await #expect(throws: MCPClientError.cancelled) { try await first.value }
            #expect(await client.snapshot().connectionID == nil)
            let replacement = try await client.connect(configuration: config)
            #expect(replacement.connectionID != original.connectionID)
            let tools = try await client.discoverTools()
            #expect(tools.count == 5)
            await client.disconnect()
        } catch {
            await client.disconnect()
            throw error
        }
    }

    @Test func coalescedDiscoveryBoundsSuspendedCallers() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        try await withFixture("catalog_barrier", limits: .init(maximumPendingRequests: 1),
                              extraArguments: [directory.path]) { client in
            try Data().write(to: directory.appendingPathComponent("arm"))
            let admitted = Task { try await client.discoverTools() }
            try await Self.waitForMarker(directory.appendingPathComponent("entered"))
            for _ in 0..<4 {
                await #expect(throws: MCPClientError.tooManyRequests) { try await client.discoverTools() }
            }
            await #expect(throws: MCPClientError.tooManyRequests) {
                try await client.invoke(tool: "echo", arguments: .object([:]))
            }
            try Data().write(to: directory.appendingPathComponent("release"))
            #expect(try await admitted.value.count == 5)
            let result = try await client.invoke(tool: "echo", arguments: .object([:]))
            #expect(result.structuredContent?.objectValue?["catalogCallCount"] == .int(2))
            #expect(await client.snapshot().state == .connected)
        }
    }

    @Test func changedSchemaDuringRefreshRejectsPreviouslyAuthorizedInvocationBeforeDispatch() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        try await withFixture("catalog_change_barrier", extraArguments: [directory.path]) { client in
            let before = await client.snapshot().toolCatalogRevision
            try Data().write(to: directory.appendingPathComponent("arm"))
            let refresh = Task { try await client.discoverTools() }
            try await Self.waitForMarker(directory.appendingPathComponent("entered"))
            let invocation = Task { try await client.invoke(tool: "echo", arguments: .object(["oldField": .string("approved")])) }
            let release = Task {
                try await Task.sleep(for: .milliseconds(75))
                try Data().write(to: directory.appendingPathComponent("release"))
            }
            #expect(try await refresh.value.count == 5)
            await #expect(throws: MCPClientError.staleConnection) { try await invocation.value }
            try await release.value
            #expect(await client.snapshot().toolCatalogRevision > before)
            #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("invoked-echo").path))
            _ = try await client.invoke(tool: "echo", arguments: .object(["newField": .int(1)]))
            #expect(FileManager.default.fileExists(atPath: directory.appendingPathComponent("invoked-echo").path))
        }
    }

    @Test func breakpointSchemaUsesLiveRegexProperty() async throws {
        try await withFixture("proxyman") { client in
            let tools = try await client.discoverTools()
            let breakpoint = try #require(tools.first { $0.name == "create_breakpoint" })
            let properties = try #require(breakpoint.inputSchema.objectValue?["properties"]?.objectValue)
            #expect(properties.keys.contains("use_regex") == true)
            #expect(properties.keys.contains("is_regex") == false)
        }
    }

    @Test func blacklistSchemaAndResultPreserveExplicitAction() async throws {
        try await withFixture("proxyman") { client in
            let tools = try await client.discoverTools()
            let blacklist = try #require(tools.first { $0.name == "create_blacklist" })
            let properties = try #require(blacklist.inputSchema.objectValue?["properties"]?.objectValue)
            let action = try #require(properties["action"]?.objectValue)
            let values = try #require(action["enum"]?.arrayValue)
            let actions = try values.map { try #require($0.stringValue) }
            #expect(actions == ["block", "block_and_hide"])
            #expect(properties.keys.contains("use_regex") == false)
            #expect(properties.keys.contains("is_regex") == false)
            let result = try await client.invoke(tool: "create_blacklist", arguments: .object([
                "url": .string("https://api.example.test/x"), "method": .string("GET"),
                "include_paths": .bool(false), "action": .string("block")
            ]))
            let rule = try #require(result.structuredContent?.objectValue?["rule"]?.objectValue)
            #expect(rule["id"]?.stringValue == "fixture-rule-1")
            #expect(rule["kind"]?.stringValue == "blacklist")
            #expect(rule["action"]?.stringValue == "block")
        }
    }

    private static func waitForMarker(_ url: URL) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !FileManager.default.fileExists(atPath: url.path) {
            guard ContinuousClock.now < deadline else { throw MCPClientError.deadlineExceeded }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
}

private actor FixtureFailureRecorder {
    var error: MCPClientError?
    func record(_ error: MCPClientError) { self.error = error }
}
