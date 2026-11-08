import Foundation
import ExternalMCP

/// Owns review receipts, but never launches or terminates the Proxyman application.
public actor ProxymanInstallationService: ProxymanInstallationManaging {
    private let authorityID = UUID()
    private var reviews: [UUID: ProxymanInstallationReview] = [:]
    private let evaluator: any CodeRequirementEvaluating
    private let store: any ProxymanBuildConfirmationStoring
    private let now: @Sendable () -> Date
    private let reviewLifetime: TimeInterval = 300
    private let approvedLifetime: TimeInterval = 28_800

    public init(evaluator: any CodeRequirementEvaluating,
                store: any ProxymanBuildConfirmationStoring,
                now: @escaping @Sendable () -> Date) {
        self.evaluator = evaluator
        self.store = store
        self.now = now
    }

    public func inspect(applicationURL: URL) async throws -> ProxymanInstallationReview {
        let review = try await inspectFiles(applicationURL: applicationURL)
        let instant = now()
        reviews = reviews.filter {
            let age = instant.timeIntervalSince($0.value.inspectedAt)
            return age >= 0 && age <= reviewLifetime
        }
        guard reviews.count < 8 else { throw ProxymanInstallationError.reviewExpired }
        reviews[review.id] = review
        return review
    }

    /// Call from a person's explicit confirmation action, never a vendor tool.
    public func confirmAndApprove(reviewID: UUID) async throws -> ApprovedProxymanInstallation {
        let review = try consumeLiveReview(reviewID)
        await store.confirm(cdhash: review.bridgeCDHash)
        return try await approveConsumedReview(review)
    }

    public func approve(reviewID: UUID) async throws -> ApprovedProxymanInstallation {
        let review = try consumeLiveReview(reviewID)
        return try await approveConsumedReview(review)
    }

    private func consumeLiveReview(_ id: UUID) throws -> ProxymanInstallationReview {
        guard let review = reviews.removeValue(forKey: id) else {
            throw ProxymanInstallationError.reviewExpired
        }
        let age = now().timeIntervalSince(review.inspectedAt)
        guard age >= 0 && age <= reviewLifetime else {
            throw ProxymanInstallationError.reviewExpired
        }
        return review
    }

    private func approveConsumedReview(_ review: ProxymanInstallationReview) async throws -> ApprovedProxymanInstallation {
        guard await store.isConfirmed(cdhash: review.bridgeCDHash) else {
            throw ProxymanInstallationError.confirmationRequired
        }
        return ApprovedProxymanInstallation(review: review, authorityID: authorityID)
    }

    public func connectionConfiguration(for approval: ApprovedProxymanInstallation) async throws -> MCPConnectionConfiguration {
        let age = now().timeIntervalSince(approval.review.inspectedAt)
        guard approval.authorityID == authorityID, age >= 0 && age < approvedLifetime else {
            throw ProxymanInstallationError.reviewExpired
        }
        let current = try await inspectFiles(applicationURL: approval.review.applicationURL)
        guard current.applicationURL == approval.review.applicationURL,
              current.bridgeURL == approval.review.bridgeURL,
              current.bundleIdentifier == approval.review.bundleIdentifier,
              current.signingTeamIdentifier == approval.review.signingTeamIdentifier,
              current.applicationCDHash == approval.review.applicationCDHash,
              current.bridgeCDHash == approval.review.bridgeCDHash,
              current.bridgeSHA256 == approval.review.bridgeSHA256 else {
            throw ProxymanInstallationError.installationChanged
        }
        return MCPConnectionConfiguration(executableURL: current.bridgeURL,
                                          expectedExecutableSHA256: current.bridgeSHA256)
    }

    public func validatedApplicationURL(for approval: ApprovedProxymanInstallation) async throws -> URL {
        _ = try await connectionConfiguration(for: approval)
        return approval.review.applicationURL
    }

    public func discardReviews() { reviews.removeAll() }

    private func inspectFiles(applicationURL: URL) async throws -> ProxymanInstallationReview {
        try Task.checkCancellation()
        guard applicationURL.isFileURL else { throw ProxymanInstallationError.invalidApplication }
        let app = applicationURL.standardizedFileURL
        guard app.path == app.resolvingSymlinksInPath().path, app.pathExtension.lowercased() == "app",
              let bundle = Bundle(url: app),
              let identifier = bundle.bundleIdentifier,
              identifier == ProxymanInstallationContract.applicationBundleIdentifier else {
            throw ProxymanInstallationError.invalidApplication
        }
        let bridge = app.appendingPathComponent(ProxymanInstallationContract.bridgeRelativePath, isDirectory: false)
        guard bridge.path == bridge.resolvingSymlinksInPath().path,
              FileManager.default.isExecutableFile(atPath: bridge.path) else {
            throw ProxymanInstallationError.missingBridge
        }
        let values = try bridge.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true, let size = values.fileSize,
              size > 0, size <= 256 * 1_024 * 1_024 else {
            throw ProxymanInstallationError.missingBridge
        }
        for url in [app, app.appendingPathComponent("Contents"), app.appendingPathComponent("Contents/MacOS"), bridge] {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let permissions = attributes[.posixPermissions] as? NSNumber,
                  permissions.uint16Value & 0o022 == 0 else {
                throw ProxymanInstallationError.untrustedPermissions
            }
        }
        let appFacts = try verifiedFacts(at: app,
            requirement: ProxymanInstallationContract.applicationRequirement,
            identifier: ProxymanInstallationContract.applicationBundleIdentifier)
        let bridgeFacts = try verifiedFacts(at: bridge,
            requirement: ProxymanInstallationContract.bridgeRequirement,
            identifier: ProxymanInstallationContract.bridgeSigningIdentifier)
        guard let team = appFacts.teamIdentifier, let appHash = appFacts.cdhash,
              let bridgeHash = bridgeFacts.cdhash else { throw ProxymanInstallationError.invalidSignature }
        let digest = try await MCPExecutableValidation.sha256(at: bridge)
        try Task.checkCancellation()
        let confirmed = await store.isConfirmed(cdhash: bridgeHash)
        return ProxymanInstallationReview(
            id: UUID(), applicationURL: app, bridgeURL: bridge, bundleIdentifier: identifier,
            applicationVersion: String((bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown").prefix(64)),
            applicationBuild: String((bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "Unknown").prefix(64)),
            signingTeamIdentifier: team, applicationCDHash: appHash, bridgeCDHash: bridgeHash,
            bridgeSHA256: digest, inspectedAt: now(), trust: confirmed ? .trusted : .confirmationRequired
        )
    }

    private func verifiedFacts(at url: URL, requirement: String, identifier: String) throws -> CodeSigningFacts {
        let facts: CodeSigningFacts
        do { facts = try evaluator.evaluate(codeAt: url, requirement: requirement) }
        catch { throw ProxymanInstallationError.invalidSignature }
        guard !facts.isAdHoc else { throw ProxymanInstallationError.adHocSignature }
        guard facts.teamIdentifier != nil, facts.signingIdentifier != nil, facts.cdhash != nil else {
            throw ProxymanInstallationError.invalidSignature
        }
        guard facts.requirementSatisfied,
              facts.teamIdentifier == ProxymanInstallationContract.signingTeamIdentifier,
              facts.signingIdentifier == identifier else {
            throw ProxymanInstallationError.untrustedSigner
        }
        guard facts.hardenedRuntime else { throw ProxymanInstallationError.hardenedRuntimeMissing }
        return facts
    }
}
