import Foundation
import Synchronization
import Testing
import ExternalMCP
@testable import ProxymanInstallation

private let applicationHash = String(repeating: "a", count: 40)
private let bridgeHash = String(repeating: "b", count: 40)
private let updatedBridgeHash = String(repeating: "c", count: 40)
private let bridgeDigest = "8d0800fb7ed991889f709898c9d69159abd725031bcc17b728aa7622e60d4767"
private let origin = Date(timeIntervalSince1970: 1_767_225_600)

private final class TestClock: Sendable {
    private let instant = Mutex(origin)
    func now() -> Date { instant.withLock { $0 } }
    func set(_ offset: TimeInterval) { instant.withLock { $0 = origin.addingTimeInterval(offset) } }
}

private final class RecordingEvaluator: CodeRequirementEvaluating {
    struct State: Sendable {
        var application = CodeSigningFacts(signingIdentifier: "com.proxyman.NSProxy",
            teamIdentifier: "3X57WP8E8V", cdhash: applicationHash,
            hardenedRuntime: true, isAdHoc: false, requirementSatisfied: true)
        var bridge = CodeSigningFacts(signingIdentifier: "mcp-server",
            teamIdentifier: "3X57WP8E8V", cdhash: bridgeHash,
            hardenedRuntime: true, isAdHoc: false, requirementSatisfied: true)
        var throwsForApplication = false
        var calls: [(URL, String)] = []
    }
    private let state = Mutex(State())
    func change(_ update: (inout State) -> Void) { state.withLock { update(&$0) } }
    func calls() -> [(URL, String)] { state.withLock { $0.calls } }
    func evaluate(codeAt url: URL, requirement: String) throws -> CodeSigningFacts {
        try state.withLock { state in
            state.calls.append((url, requirement))
            if url.pathExtension == "app" {
                if state.throwsForApplication { throw ProxymanInstallationError.invalidSignature }
                return state.application
            }
            return state.bridge
        }
    }
}

private struct FakeApplication: Sendable {
    let base: URL
    let application: URL
    var bridge: URL { application.appendingPathComponent("Contents/MacOS/mcp-server") }

    init(identifier: String = "com.proxyman.NSProxy") throws {
        base = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        application = base.appendingPathComponent("Proxyman.app", isDirectory: true)
        let contents = application.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        for directory in [base, application, contents, macOS] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                   attributes: [.posixPermissions: 0o755])
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        }
        let info = ["CFBundleIdentifier": identifier, "CFBundleShortVersionString": "26.4.0",
                    "CFBundleVersion": "260400", "CFBundlePackageType": "APPL"]
        let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try data.write(to: contents.appendingPathComponent("Info.plist"))
        try Data("fixture-bridge-v1".utf8).write(to: bridge)
        try setMode(0o755, at: bridge)
    }

    func setMode(_ mode: Int, at url: URL) throws {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }
    func remove() { try? FileManager.default.removeItem(at: base) }
}

private func makeService(_ evaluator: RecordingEvaluator = RecordingEvaluator(),
                         store: InMemoryProxymanBuildConfirmationStore = .init(),
                         clock: TestClock = .init()) -> ProxymanInstallationService {
    ProxymanInstallationService(evaluator: evaluator, store: store, now: { clock.now() })
}

@Test func inspectionReportsBuildAuditAndRequiresConfirmation() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let review = try await makeService().inspect(applicationURL: app.application)
    #expect(review.bundleIdentifier == "com.proxyman.NSProxy")
    #expect(review.applicationVersion == "26.4.0")
    #expect(review.applicationBuild == "260400")
    #expect(review.signingTeamIdentifier == "3X57WP8E8V")
    #expect(review.applicationCDHash == applicationHash)
    #expect(review.bridgeCDHash == bridgeHash)
    #expect(review.bridgeSHA256 == bridgeDigest)
    #expect(review.inspectedAt == origin)
    #expect(review.trust == .confirmationRequired)
}

@Test func confirmedBridgeBuildCanBeApproved() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let service = makeService(store: store)
    let review = try await service.inspect(applicationURL: app.application)
    #expect(review.trust == .trusted)
    let approval = try await service.approve(reviewID: review.id)
    #expect(approval.review.applicationURL == review.applicationURL)

    let initiallyEmptyStore = InMemoryProxymanBuildConfirmationStore()
    let freshService = makeService(store: initiallyEmptyStore)
    let awaitingConfirmation = try await freshService.inspect(applicationURL: app.application)
    #expect(awaitingConfirmation.trust == .confirmationRequired)
    await initiallyEmptyStore.confirm(cdhash: bridgeHash)
    let subsequentlyApproved = try await freshService.approve(reviewID: awaitingConfirmation.id)
    #expect(subsequentlyApproved.review.applicationURL == awaitingConfirmation.applicationURL)
}

@Test func explicitConfirmationRecordsOnlyTheReviewedBridgeBuild() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let store = InMemoryProxymanBuildConfirmationStore()
    let service = makeService(store: store)
    let first = try await service.inspect(applicationURL: app.application)
    await #expect(throws: ProxymanInstallationError.confirmationRequired) {
        try await service.approve(reviewID: first.id)
    }
    #expect(await store.isConfirmed(cdhash: bridgeHash) == false)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await service.confirmAndApprove(reviewID: first.id)
    }
    #expect(await store.isConfirmed(cdhash: bridgeHash) == false)
    let second = try await service.inspect(applicationURL: app.application)
    _ = try await service.confirmAndApprove(reviewID: second.id)
    #expect(await store.isConfirmed(cdhash: bridgeHash) == true)
    let third = try await service.inspect(applicationURL: app.application)
    #expect(third.trust == .trusted)

    let unknownStore = InMemoryProxymanBuildConfirmationStore()
    let unknownService = makeService(store: unknownStore)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await unknownService.confirmAndApprove(reviewID: UUID())
    }
    #expect(await unknownStore.isConfirmed(cdhash: bridgeHash) == false)

    let ownerStore = InMemoryProxymanBuildConfirmationStore()
    let owner = makeService(store: ownerStore)
    let foreignStore = InMemoryProxymanBuildConfirmationStore()
    let foreignService = makeService(store: foreignStore)
    let ownedReview = try await owner.inspect(applicationURL: app.application)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await foreignService.confirmAndApprove(reviewID: ownedReview.id)
    }
    #expect(await ownerStore.isConfirmed(cdhash: bridgeHash) == false)
    #expect(await foreignStore.isConfirmed(cdhash: bridgeHash) == false)

    let expiredStore = InMemoryProxymanBuildConfirmationStore()
    let expiryClock = TestClock()
    let expiryService = makeService(store: expiredStore, clock: expiryClock)
    let expiredReview = try await expiryService.inspect(applicationURL: app.application)
    expiryClock.set(301)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await expiryService.confirmAndApprove(reviewID: expiredReview.id)
    }
    #expect(await expiredStore.isConfirmed(cdhash: bridgeHash) == false)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await expiryService.confirmAndApprove(reviewID: expiredReview.id)
    }
    #expect(await expiredStore.isConfirmed(cdhash: bridgeHash) == false)
}

@Test func updatedBridgeBuildNeedsNewConfirmation() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let evaluator = RecordingEvaluator()
    evaluator.change { $0.bridge.cdhash = updatedBridgeHash }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let review = try await makeService(evaluator, store: store).inspect(applicationURL: app.application)
    #expect(review.trust == .confirmationRequired)
    #expect(await store.isConfirmed(cdhash: updatedBridgeHash) == false)
}

@Test func adHocSignaturesTakePrecedenceOverMissingIdentity() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    for variant in 0..<3 {
        let evaluator = RecordingEvaluator()
        evaluator.change {
            if variant == 1 { $0.application.isAdHoc = true }
            else { $0.bridge.isAdHoc = true }
            if variant == 2 { $0.bridge.teamIdentifier = nil }
        }
        let service = makeService(evaluator)
        await #expect(throws: ProxymanInstallationError.adHocSignature) {
            try await service.inspect(applicationURL: app.application)
        }
    }
}

@Test func storedConfirmationCannotOverrideAdHocSignature() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let evaluator = RecordingEvaluator()
    evaluator.change { $0.bridge.isAdHoc = true }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let service = makeService(evaluator, store: store)
    await #expect(throws: ProxymanInstallationError.adHocSignature) {
        try await service.inspect(applicationURL: app.application)
    }
}

@Test func requirementTeamAndIdentifierMustAllMatch() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    for variant in 0..<3 {
        let evaluator = RecordingEvaluator()
        evaluator.change {
            if variant == 0 { $0.bridge.teamIdentifier = "ZZZZZZZZZZ" }
            if variant == 1 { $0.bridge.requirementSatisfied = false }
            if variant == 2 { $0.bridge.signingIdentifier = "other" }
        }
        let service = makeService(evaluator)
        await #expect(throws: ProxymanInstallationError.untrustedSigner) {
            try await service.inspect(applicationURL: app.application)
        }
    }
}

@Test func bothItemsRequireHardenedRuntime() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    for application in [true, false] {
        let evaluator = RecordingEvaluator()
        evaluator.change {
            if application { $0.application.hardenedRuntime = false }
            else { $0.bridge.hardenedRuntime = false }
        }
        let service = makeService(evaluator)
        await #expect(throws: ProxymanInstallationError.hardenedRuntimeMissing) {
            try await service.inspect(applicationURL: app.application)
        }
    }
}

@Test func failedEvaluationAndMissingIdentityAreInvalidSignatures() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    for variant in 0..<4 {
        let evaluator = RecordingEvaluator()
        evaluator.change {
            if variant == 0 { $0.throwsForApplication = true }
            if variant == 1 { $0.application.teamIdentifier = nil }
            if variant == 2 { $0.bridge.signingIdentifier = nil }
            if variant == 3 { $0.bridge.cdhash = nil }
        }
        let service = makeService(evaluator)
        await #expect(throws: ProxymanInstallationError.invalidSignature) {
            try await service.inspect(applicationURL: app.application)
        }
    }
}

@Test func unrelatedAndSetappBundlesAreRejectedBeforeEvaluation() async throws {
    for identifier in ["com.example.Other", "com.proxyman.NSProxy-setapp"] {
        let app = try FakeApplication(identifier: identifier); defer { app.remove() }
        let evaluator = RecordingEvaluator()
        let service = makeService(evaluator)
        await #expect(throws: ProxymanInstallationError.invalidApplication) {
            try await service.inspect(applicationURL: app.application)
        }
        #expect(evaluator.calls().isEmpty)
    }
}

@Test func bridgeMustBePresentRegularNonSymlinkAndExecutable() async throws {
    for variant in 0..<3 {
        let app = try FakeApplication(); defer { app.remove() }
        if variant == 0 { try FileManager.default.removeItem(at: app.bridge) }
        if variant == 1 {
            let destination = app.base.appendingPathComponent("regular-bridge")
            try FileManager.default.moveItem(at: app.bridge, to: destination)
            try FileManager.default.createSymbolicLink(at: app.bridge, withDestinationURL: destination)
        }
        if variant == 2 { try app.setMode(0o644, at: app.bridge) }
        let evaluator = RecordingEvaluator()
        let service = makeService(evaluator)
        await #expect(throws: ProxymanInstallationError.missingBridge) {
            try await service.inspect(applicationURL: app.application)
        }
        #expect(evaluator.calls().isEmpty)
    }
}

@Test func writableBridgeOrContainingDirectoryIsRejected() async throws {
    for bridge in [true, false] {
        let app = try FakeApplication(); defer { app.remove() }
        try app.setMode(bridge ? 0o775 : 0o777,
                        at: bridge ? app.bridge : app.application.appendingPathComponent("Contents/MacOS"))
        let service = makeService()
        await #expect(throws: ProxymanInstallationError.untrustedPermissions) {
            try await service.inspect(applicationURL: app.application)
        }
    }
}

@Test func applicationRequiresBundleSuffixCanonicalPathAndFileScheme() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let renamed = app.base.appendingPathComponent("Proxyman.bundle", isDirectory: true)
    try FileManager.default.moveItem(at: app.application, to: renamed)
    let link = app.base.appendingPathComponent("Linked.app", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: renamed)
    let remote = try #require(URL(string: "https://example.test/Proxyman.app"))
    for url in [renamed, link, remote] {
        let service = makeService()
        await #expect(throws: ProxymanInstallationError.invalidApplication) {
            try await service.inspect(applicationURL: url)
        }
    }
}

@Test func connectionUsesFreshDigestAndMinimalEnvironment() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let service = makeService(store: store)
    let review = try await service.inspect(applicationURL: app.application)
    let approval = try await service.approve(reviewID: review.id)
    let configuration = try await service.connectionConfiguration(for: approval)
    #expect(configuration.executableURL == app.bridge)
    #expect(configuration.expectedExecutableSHA256 == bridgeDigest)
    #expect(configuration.arguments == [String]())
    #expect(Set(configuration.environment.keys) == Set(["HOME", "LANG", "LC_ALL", "TMPDIR"]))
}

@Test func changedBridgeBytesOrCodeIdentityInvalidatesApproval() async throws {
    for changeBytes in [true, false] {
        let app = try FakeApplication(); defer { app.remove() }
        let evaluator = RecordingEvaluator()
        let store = InMemoryProxymanBuildConfirmationStore()
        await store.confirm(cdhash: bridgeHash)
        let service = makeService(evaluator, store: store)
        let review = try await service.inspect(applicationURL: app.application)
        let approval = try await service.approve(reviewID: review.id)
        if changeBytes {
            try Data("fixture-bridge-v2".utf8).write(to: app.bridge)
            try app.setMode(0o755, at: app.bridge)
            let digest = try await MCPExecutableValidation.sha256(at: app.bridge)
            #expect(digest == "c2ac234f19dfab7320d55e2e3d183cdfcf47a3479804c96a63b8a063ab849f6a")
        } else { evaluator.change { $0.bridge.cdhash = updatedBridgeHash } }
        await #expect(throws: ProxymanInstallationError.installationChanged) {
            try await service.connectionConfiguration(for: approval)
        }
    }
}

@Test func injectedClockEnforcesInclusiveReviewAndExclusiveApprovalExpiry() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let clock = TestClock()
    let service = makeService(store: store, clock: clock)
    let first = try await service.inspect(applicationURL: app.application)
    let second = try await service.inspect(applicationURL: app.application)
    let third = try await service.inspect(applicationURL: app.application)
    let approval = try await service.approve(reviewID: third.id)
    clock.set(300)
    _ = try await service.approve(reviewID: first.id)
    clock.set(301)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await service.approve(reviewID: second.id)
    }
    clock.set(28_799)
    _ = try await service.connectionConfiguration(for: approval)
    clock.set(28_800)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await service.connectionConfiguration(for: approval)
    }
}

@Test func anotherServiceCannotUseAnApproval() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let first = makeService(store: store)
    let second = makeService(store: store)
    let review = try await first.inspect(applicationURL: app.application)
    let approval = try await first.approve(reviewID: review.id)
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await second.connectionConfiguration(for: approval)
    }
}

@Test func liveReviewCountIsBoundedAndExpiredSlotsAreReclaimed() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let clock = TestClock()
    let service = makeService(clock: clock)
    for _ in 0..<8 { _ = try await service.inspect(applicationURL: app.application) }
    await #expect(throws: ProxymanInstallationError.reviewExpired) {
        try await service.inspect(applicationURL: app.application)
    }
    clock.set(301)
    _ = try await service.inspect(applicationURL: app.application)
}

@Test func evaluationUsesExactRequirementsOncePerItemPerPass() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let evaluator = RecordingEvaluator()
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: bridgeHash)
    let service = makeService(evaluator, store: store)
    let review = try await service.inspect(applicationURL: app.application)
    let firstCalls = evaluator.calls()
    #expect(firstCalls.count == 2)
    let expectedApplication = "anchor apple generic and identifier \"com.proxyman.NSProxy\" and certificate leaf[subject.OU] = \"3X57WP8E8V\""
    let expectedBridge = "anchor apple generic and identifier \"mcp-server\" and certificate leaf[subject.OU] = \"3X57WP8E8V\""
    #expect(firstCalls.map(\.0) == [app.application, app.bridge])
    #expect(firstCalls.map(\.1) == [expectedApplication, expectedBridge])
    let approval = try await service.approve(reviewID: review.id)
    _ = try await service.connectionConfiguration(for: approval)
    let calls = evaluator.calls()
    #expect(calls.count == 4)
    #expect(calls.map(\.0) == [app.application, app.bridge, app.application, app.bridge])
    #expect(calls.map(\.1) == [expectedApplication, expectedBridge, expectedApplication, expectedBridge])
}

@Test func applicationHashConfirmationDoesNotConfirmTheBridge() async throws {
    let app = try FakeApplication(); defer { app.remove() }
    let store = InMemoryProxymanBuildConfirmationStore()
    await store.confirm(cdhash: applicationHash)
    let service = makeService(store: store)
    let review = try await service.inspect(applicationURL: app.application)
    #expect(review.trust == .confirmationRequired)
    #expect(review.applicationCDHash == applicationHash)
    #expect(review.bridgeCDHash == bridgeHash)
    await #expect(throws: ProxymanInstallationError.confirmationRequired) {
        try await service.approve(reviewID: review.id)
    }
}

@Test func realEvaluatorDistinguishesMismatchFromMissingAndUnsignedCode() throws {
    let evaluator = SecurityFrameworkRequirementEvaluator()
    let facts = try evaluator.evaluate(codeAt: URL(fileURLWithPath: "/usr/bin/true"),
                                       requirement: ProxymanInstallationContract.bridgeRequirement)
    #expect(facts.requirementSatisfied == false)
    #expect(facts.teamIdentifier == nil)
    let app = try FakeApplication(); defer { app.remove() }
    #expect(throws: (any Error).self) {
        try evaluator.evaluate(codeAt: app.base.appendingPathComponent("missing"),
                               requirement: ProxymanInstallationContract.bridgeRequirement)
    }
    #expect(throws: (any Error).self) {
        try evaluator.evaluate(codeAt: app.bridge, requirement: ProxymanInstallationContract.bridgeRequirement)
    }
}
