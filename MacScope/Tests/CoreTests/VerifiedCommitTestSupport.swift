import Foundation
import XCTest
@testable import MacScope

// Shared fixtures for the VA3b joined receipt and annotation commit tests. The projector here is a
// test-only fixture: the production projector belongs to VA4. Its digest covers exactly the
// address-override map, and its revision is the accepted-record count, matching the service rule.

@MainActor
final class VerifiedCommitProjector: VerifiedAnnotationProjecting {
    private(set) var calls = 0
    /// 1-based call number on which the stamp is deliberately wrong (a perturbed post-install read).
    var lieOnCall: Int?

    static func digest(_ overrides: [ImageAddress: AddressOverride]) -> String {
        let data = (try? VACanonicalJSON.encode(WorkspacePackageAnalysis.entries(from: overrides))) ?? Data()
        return VerifiedAnnotationAuditCodec.sha256Hex(data)
    }

    func stamp(workspaceID: UUID, documentID: UUID, installationID: UUID,
               snapshot: WorkspaceSnapshot, revision: UInt64) throws -> VAProjectionStamp {
        calls += 1
        let digest = calls == lieOnCall
            ? String(repeating: "0", count: 64)
            : Self.digest(snapshot.addressOverrides)
        return VAProjectionStamp(workspaceID: workspaceID, documentID: documentID,
                                 installationID: installationID, revision: revision, digest: digest)
    }
}

extension VerifiedAnnotationCommitOutcome {
    var refusalCode: VerifiedAnnotationCommitRefusal.Code? {
        if case .refused(let refusal) = self { return refusal.code }
        return nil
    }
    var indeterminateCode: VerifiedAnnotationCommitIndeterminate.Code? {
        if case .indeterminate(let value) = self { return value.code }
        return nil
    }
    var isCommitted: Bool { if case .committed = self { return true } else { return false } }
    var isExisting: Bool { if case .existing = self { return true } else { return false } }
    var description: String {
        switch self {
        case .committed(_, let info): return "committed(installed: \(info.annotationInstalled), degraded: \(info.journalDegraded))"
        case .existing: return "existing"
        case .refused(let refusal): return "refused(\(refusal.code.rawValue), \(refusal.detail ?? "-"))"
        case .indeterminate(let value): return "indeterminate(\(value.code.rawValue), \(value.detail ?? "-"))"
        }
    }
}

struct VCDisk {
    let overrides: [ImageAddress: AddressOverride]
    let operationIDs: [UUID]
    let envelope: VerifiedAnnotationAuditEnvelope?
}

/// Canonical dump used to compare "nothing changed" across every refusal path.
struct VCDump: Equatable {
    let overridesDigest: String
    let envelopeBytes: Data
    let dirty: Bool
    let generation: WorkspaceDocumentMutationGeneration
    let canUndo: Bool
    let installation: UUID
}

@MainActor
enum VCFixture {
    static let code = Data([
        0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
        0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6
    ])

    struct Store {
        let store: WorkspaceStore
        let binary: URL
        let base: UInt64
        let root: URL
        @MainActor var key: ImageAddress { ImageAddress(slot: store.snapshot.primarySlot, address: base) }
        @MainActor var other: ImageAddress { ImageAddress(slot: store.snapshot.primarySlot, address: base + 4) }
    }

    static func makeStore(_ test: XCTestCase) throws -> Store {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("va3b-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let macho = TinyMachO.make(code: code)
        let binary = try macho.write()
        test.addTeardownBlock {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: binary.deletingLastPathComponent())
        }
        let engine = AnalysisEngine()
        let store = WorkspaceStore(workspaceName: "va3b", snapshot: try engine.analyze(url: binary),
                                   engine: engine, autosaveScheduler: nil)
        store.recents = VCQuietRecents()
        return Store(store: store, binary: binary, base: macho.baseAddress, root: root)
    }

    static func dump(_ store: WorkspaceStore) -> VCDump {
        VCDump(
            overridesDigest: VerifiedCommitProjector.digest(store.snapshot.addressOverrides),
            envelopeBytes: (try? VerifiedAnnotationAuditCodec.encode(store.verifiedAnnotationAudit)) ?? Data(),
            dirty: store.hasUnsavedChanges, generation: store.mutationGeneration,
            canUndo: store.undoManager.canUndo, installation: store.documentInstallationID)
    }

    static func request(
        _ store: WorkspaceStore, key: ImageAddress, name: String? = "verified-name",
        accepted: Bool = true, id: UUID = UUID(), rationale: String = "VA3b commit test",
        projector: VerifiedCommitProjector = VerifiedCommitProjector(), expecting: String? = nil,
        field: VerifiedAnnotationField = .name
    ) throws -> VerifiedAnnotationCommitRequest {
        let accepts = UInt64(store.verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count)
        func stamp(_ overrides: [ImageAddress: AddressOverride], _ revision: UInt64) -> VAProjectionStamp {
            VAProjectionStamp(workspaceID: store.workspaceID, documentID: store.documentID,
                              installationID: store.documentInstallationID, revision: revision,
                              digest: VerifiedCommitProjector.digest(overrides))
        }
        let before = stamp(store.snapshot.addressOverrides, accepts)
        var candidate = store.snapshot.addressOverrides
        if accepted {
            var target = candidate[key] ?? AddressOverride()
            field.set(name, in: &target)
            candidate[key] = target.isEmpty ? nil : target
        }
        let after = accepted ? stamp(candidate, accepts + 1) : nil
        let evidenceID = UUID()
        let mutation = VAMutationRequest(
            id: id, base: before,
            edits: [VAEditIntent(target: VATargetReference(componentID: UUID(), function: VAAddress64(key.address)),
                                 kind: field == .name ? .functionName : .functionComment,
                                 value: name, evidenceIDs: [evidenceID])],
            rationale: rationale)
        let receipt = try VAVerificationReceipt(
            request: mutation, decision: accepted ? .accepted : .rejected, before: before, after: after,
            mechanical: accepted ? .candidateReadbackVerified : .notVerified,
            persistence: accepted ? .pendingFreshProcessCheckpoint : .notApplicable,
            failure: accepted ? nil : "candidate mismatch", recordedAt: Date(timeIntervalSince1970: 1234.5))
        let projection = VAWorkspaceProjection(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, revision: accepts, components: [])
        return VerifiedAnnotationCommitRequest(
            state: VAVerificationState(projection: projection, receipts: [receipt]), receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))],
            target: accepted ? key : nil, field: accepted ? field : nil, requested: accepted ? name : nil,
            expectingVersion: expecting ?? store.verifiedCommitVersionToken(), projector: projector)
    }

    /// A defined struct type the typed commit can name (S4 tests). Returns its definition.
    @discardableResult
    static func addType(_ store: WorkspaceStore, _ name: String = "Header") -> TypeDefinition {
        let definition = TypeDefinition(kind: .struct, name: name)
        store.upsertTypeDefinition(definition)
        return definition
    }

    /// Type-at-address request (VA-SCOPE S4): `fieldClass: .addressType`, one `addressType` edit whose
    /// value is the requested type name (nil clears). The stamps use the same fixture projector as
    /// `request`, whose digest covers the override map including `appliedTypeName`.
    static func typedRequest(
        _ store: WorkspaceStore, key: ImageAddress, type: String?, accepted: Bool = true, id: UUID = UUID(),
        projector: VerifiedCommitProjector = VerifiedCommitProjector(), expecting: String? = nil
    ) throws -> VerifiedAnnotationCommitRequest {
        let accepts = UInt64(store.verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count)
        func stamp(_ overrides: [ImageAddress: AddressOverride], _ revision: UInt64) -> VAProjectionStamp {
            VAProjectionStamp(workspaceID: store.workspaceID, documentID: store.documentID,
                              installationID: store.documentInstallationID, revision: revision,
                              digest: VerifiedCommitProjector.digest(overrides))
        }
        let before = stamp(store.snapshot.addressOverrides, accepts)
        var candidate = store.snapshot.addressOverrides
        if accepted {
            var target = candidate[key] ?? AddressOverride()
            VerifiedFieldClass.addressType.set(type, in: &target)
            candidate[key] = target.isEmpty ? nil : target
        }
        let after = accepted ? stamp(candidate, accepts + 1) : nil
        let evidenceID = UUID()
        let mutation = VAMutationRequest(
            id: id, base: before,
            edits: [VAEditIntent(target: VATargetReference(componentID: UUID(), function: VAAddress64(key.address)),
                                 kind: .addressType, value: type, evidenceIDs: [evidenceID])],
            rationale: "S4 typed commit test")
        let receipt = try VAVerificationReceipt(
            request: mutation, decision: accepted ? .accepted : .rejected, before: before, after: after,
            mechanical: accepted ? .candidateReadbackVerified : .notVerified,
            persistence: accepted ? .pendingFreshProcessCheckpoint : .notApplicable,
            failure: accepted ? nil : "candidate mismatch", recordedAt: Date(timeIntervalSince1970: 1234.5))
        let projection = VAWorkspaceProjection(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, revision: accepts, components: [])
        return VerifiedAnnotationCommitRequest(
            state: VAVerificationState(projection: projection, receipts: [receipt]), receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))],
            target: accepted ? key : nil, fieldClass: accepted ? .addressType : nil, requested: accepted ? type : nil,
            expectingVersion: expecting ?? store.verifiedCommitVersionToken(), projector: projector)
    }

    /// Function signature request (VA-SCOPE S6b): `fieldClass: .functionSignature`, one `functionPrototype` edit
    /// whose value is the canonical signature text (nil clears). `production` stamps with the real
    /// `NativeAnnotationProjector` (canonical content only); otherwise the fixture projector digest is used,
    /// which covers the full override entries (rowTokens included). `rawText` replaces the canonical value for
    /// invalid-value tests; the after-stamp then equals the before-stamp because no valid candidate exists.
    static func signatureRequest(
        _ store: WorkspaceStore, key: ImageAddress, signature: FunctionSignatureOverride?, rawText: String? = nil,
        accepted: Bool = true, id: UUID = UUID(), production: Bool = false, expecting: String? = nil
    ) throws -> VerifiedAnnotationCommitRequest {
        let text = try rawText ?? signature.map(VerifiedFieldCodec.canonicalSignature)
        let projector: any VerifiedAnnotationProjecting = production ? NativeAnnotationProjector() : VerifiedCommitProjector()
        let accepts = UInt64(store.verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count)
        func stamp(_ overrides: [ImageAddress: AddressOverride], _ revision: UInt64) -> VAProjectionStamp {
            VAProjectionStamp(workspaceID: store.workspaceID, documentID: store.documentID,
                              installationID: store.documentInstallationID, revision: revision,
                              digest: production ? NativeAnnotationProjector.digest(overrides)
                                                 : VerifiedCommitProjector.digest(overrides))
        }
        let before = stamp(store.snapshot.addressOverrides, accepts)
        var candidate = store.snapshot.addressOverrides
        if accepted && rawText == nil {
            var target = candidate[key] ?? AddressOverride()
            VerifiedFieldClass.functionSignature.set(text, in: &target)
            candidate[key] = target.isEmpty ? nil : target
        }
        let after = accepted ? stamp(candidate, accepts + 1) : nil
        let evidenceID = UUID()
        let mutation = VAMutationRequest(
            id: id, base: before,
            edits: [VAEditIntent(target: VATargetReference(componentID: UUID(), function: VAAddress64(key.address)),
                                 kind: .functionPrototype, value: text, evidenceIDs: [evidenceID])],
            rationale: "S6b signature commit test")
        let receipt = try VAVerificationReceipt(
            request: mutation, decision: accepted ? .accepted : .rejected, before: before, after: after,
            mechanical: accepted ? .candidateReadbackVerified : .notVerified,
            persistence: accepted ? .pendingFreshProcessCheckpoint : .notApplicable,
            failure: accepted ? nil : "candidate mismatch", recordedAt: Date(timeIntervalSince1970: 1234.5))
        let projection = VAWorkspaceProjection(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, revision: accepts, components: [])
        return VerifiedAnnotationCommitRequest(
            state: VAVerificationState(projection: projection, receipts: [receipt]), receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))],
            target: accepted ? key : nil, fieldClass: accepted ? .functionSignature : nil, requested: accepted ? text : nil,
            expectingVersion: expecting ?? store.verifiedCommitVersionToken(), projector: projector)
    }

    /// Builds a signature the way the editor does, with explicit row tokens.
    static func signature(_ rows: [(token: String, name: String, type: String)], returnType: String? = "int")
        -> FunctionSignatureOverride {
        FunctionSignatureOverride(returnType: returnType, args: rows.map { ArgOverride(rowToken: $0.token, name: $0.name, type: $0.type) })
    }

    static func disk(_ location: WorkspaceDocumentLocation) async throws -> VCDisk {
        // The publisher replaces the package directory, so a location captured before the commit
        // carries a stale file-object identity: read by path with a fresh identity.
        let fresh = try WorkspaceDocumentLocation.canonicalized(from: location.canonicalURL)
        let package = try await WorkspaceDocumentReader().readValidated(from: fresh)
        let contents = try MacScopeDocumentPackage.validatedContents(
            manifestData: package.manifestData, attachmentsByBinaryID: package.attachmentsByBinaryID,
            reconstructionState: package.reconstructionState,
            instructionSidecarData: package.instructionSidecarData)
        let envelope = contents.manifest.verifiedAnnotationAudit
        return VCDisk(overrides: contents.snapshot.addressOverrides,
                      operationIDs: envelope?.records.map(\.operationID) ?? [], envelope: envelope)
    }

    static func tree(_ root: URL) throws -> [String: Data] {
        var files: [String: Data] = [:]
        guard let paths = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else {
            return files
        }
        for case let url as URL in paths where try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
            files[String(url.path.dropFirst(root.path.count))] = try Data(contentsOf: url)
        }
        return files
    }
}

struct VCQuietRecents: WorkspaceRecentsRecording {
    func noteRecentDocument(_ url: URL) {}
    var recentDocumentURLs: [URL] { [] }
    func clearRecentDocuments() {}
}

/// Synchronization point for tests that act while a commit is suspended inside the publisher.
actor VCGate {
    private(set) var arrived = false
    private var isOpen = false
    func pass() async {
        arrived = true
        while !isOpen { try? await Task.sleep(for: .milliseconds(5)) }
    }
    func open() { isOpen = true }
    func waitUntilArrived() async throws {
        for _ in 0..<2000 {
            if arrived { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("publisher never reached the gate")
    }
}

/// Mutable hook storage shared with the real publisher's @Sendable construction closures.
final class VCHooks: @unchecked Sendable {
    private let lock = NSLock()
    private var _beforeRename: (@Sendable () -> Void)?
    private var _afterRename: (@Sendable () throws -> Void)?
    private var _beforeDirectorySync: (@Sendable () throws -> Void)?
    private var _beforeRollback: (@Sendable () throws -> Void)?
    var beforeRename: (@Sendable () -> Void)? {
        get { lock.withLock { _beforeRename } } set { lock.withLock { _beforeRename = newValue } }
    }
    var afterRename: (@Sendable () throws -> Void)? {
        get { lock.withLock { _afterRename } } set { lock.withLock { _afterRename = newValue } }
    }
    var beforeDirectorySync: (@Sendable () throws -> Void)? {
        get { lock.withLock { _beforeDirectorySync } } set { lock.withLock { _beforeDirectorySync = newValue } }
    }
    var beforeRollback: (@Sendable () throws -> Void)? {
        get { lock.withLock { _beforeRollback } } set { lock.withLock { _beforeRollback = newValue } }
    }
}

/// Real publisher plus fault and pause seams. Everything else is the production code path.
final class VCFaultPublisher: WorkspaceDocumentPublishing, @unchecked Sendable {
    let hooks = VCHooks()
    private let real: WorkspaceDocumentPublisher
    private let lock = NSLock()
    private var _failStage = false
    private var _failBeforePublish = false
    private var _gate: VCGate?
    private var _stageCalls = 0
    private var _publishCalls = 0

    var failStage: Bool { get { lock.withLock { _failStage } } set { lock.withLock { _failStage = newValue } } }
    var failBeforePublish: Bool {
        get { lock.withLock { _failBeforePublish } } set { lock.withLock { _failBeforePublish = newValue } }
    }
    var gate: VCGate? { get { lock.withLock { _gate } } set { lock.withLock { _gate = newValue } } }
    var stageCalls: Int { lock.withLock { _stageCalls } }
    var publishCalls: Int { lock.withLock { _publishCalls } }

    init() {
        let hooks = self.hooks
        real = WorkspaceDocumentPublisher(
            beforeParentDirectorySynchronization: { try hooks.beforeDirectorySync?() },
            beforeRollbackRename: { try hooks.beforeRollback?() },
            beforeAtomicPublicationRename: { hooks.beforeRename?() },
            afterAtomicPublicationRename: { try hooks.afterRename?() })
    }

    func stage(_ payload: WorkspaceDocumentPackagePayload, in parentDirectory: URL) async throws -> WorkspaceDocumentStagedPackage {
        lock.withLock { _stageCalls += 1 }
        if failStage { throw WorkspaceDocumentSessionError.operationFailed("injected-stage-failure") }
        return try await real.stage(payload, in: parentDirectory)
    }

    func publish(_ staged: WorkspaceDocumentStagedPackage, to destination: WorkspaceDocumentLocation,
                 expecting expected: WorkspacePackageExternalVersion) async throws -> WorkspaceDocumentPublishReceipt {
        lock.withLock { _publishCalls += 1 }
        return try await real.publish(staged, to: destination, expecting: expected)
    }

    func publishGuarded(_ staged: WorkspaceDocumentStagedPackage, to destination: WorkspaceDocumentLocation,
                        expecting expected: WorkspacePackageExternalVersion,
                        commitGuard: @escaping @Sendable () -> Bool) async throws -> WorkspaceDocumentPublishReceipt {
        lock.withLock { _publishCalls += 1 }
        if failBeforePublish { throw WorkspaceDocumentSessionError.operationFailed("injected-before-publish") }
        if let gate { await gate.pass() }
        return try await real.publishGuarded(staged, to: destination, expecting: expected, commitGuard: commitGuard)
    }

    func discard(_ staged: WorkspaceDocumentStagedPackage) async { await real.discard(staged) }
}

/// Minimal single-owner reservation table plus a forced publication refusal for the
/// second-window test.
@MainActor
final class VCReservations: WorkspaceDocumentLocationReserving {
    private struct Owner { let sessionID: WorkspaceDocumentSessionID; let windowID: WorkspaceWindowID }
    private var owners: [URL: Owner] = [:]
    private var publications: [WorkspaceDocumentPublicationReservation: (Owner, Bool)] = [:]
    var refusePublication = false

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
        if refusePublication { return .alreadyOwned(WorkspaceWindowID.fresh()) }
        if let existing = owners[destination.canonicalURL], existing.windowID != windowID {
            return .alreadyOwned(existing.windowID)
        }
        let publication = WorkspaceDocumentPublicationReservation()
        publications[publication] = (Owner(sessionID: sessionID, windowID: windowID), retainingPublishedOwnership)
        return .reserved(publication)
    }
    func completePhysicalPublication(_ publication: WorkspaceDocumentPublicationReservation,
                                     at publishedLocation: WorkspaceDocumentLocation) -> WorkspaceDocumentPublicationCompletionResult {
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

/// A saved document bound to a real session with the production reader, probe and monitor.
@MainActor
final class VCSession {
    let fixture: VCFixture.Store
    let publisher = VCFaultPublisher()
    let reservations = VCReservations()
    let session: WorkspaceDocumentSession
    let location: WorkspaceDocumentLocation
    let destination: URL
    var store: WorkspaceStore { fixture.store }
    var key: ImageAddress { fixture.key }

    init(test: XCTestCase) async throws {
        fixture = try VCFixture.makeStore(test)
        destination = fixture.root.appendingPathComponent("Doc.mscope", isDirectory: true)
        let probe = WorkspacePackageVersionProbe()
        let io = WorkspaceDocumentIO(
            probe: probe, reader: WorkspaceDocumentReader(probe: probe), publisher: publisher,
            monitor: WorkspaceDocumentChangeMonitor())
        session = WorkspaceDocumentSession(
            sessionID: .init(rawValue: UUID()), windowID: .fresh(), source: fixture.store,
            io: io, reservations: reservations)
        fixture.store.bindDocumentSessionMutationObserver(session)
        let saved = await session.saveAs(to: destination)
        guard case .saved(clean: true, adopted: _) = saved else {
            XCTFail("fixture saveAs failed: \(saved)")
            throw WorkspaceDocumentSessionError.operationFailed("fixture")
        }
        location = try WorkspaceDocumentLocation.canonicalized(from: destination)
    }

    func request(name: String? = "verified-name", accepted: Bool = true, id: UUID = UUID(),
                 key: ImageAddress? = nil, rationale: String = "VA3b commit test",
                 projector: VerifiedCommitProjector = VerifiedCommitProjector(),
                 expecting: String? = nil) throws -> VerifiedAnnotationCommitRequest {
        try VCFixture.request(store, key: key ?? self.key, name: name, accepted: accepted, id: id,
                              rationale: rationale, projector: projector, expecting: expecting)
    }

    /// A non-function address inside the image (S4 typed target).
    var typedKey: ImageAddress { fixture.other }

    func typedRequest(type: String?, id: UUID = UUID(), key: ImageAddress? = nil,
                      projector: VerifiedCommitProjector = VerifiedCommitProjector(),
                      expecting: String? = nil) throws -> VerifiedAnnotationCommitRequest {
        try VCFixture.typedRequest(store, key: key ?? typedKey, type: type, id: id,
                                   projector: projector, expecting: expecting)
    }

    func signatureRequest(signature: FunctionSignatureOverride?, rawText: String? = nil, id: UUID = UUID(),
                          key: ImageAddress? = nil, production: Bool = false,
                          expecting: String? = nil) throws -> VerifiedAnnotationCommitRequest {
        try VCFixture.signatureRequest(store, key: key ?? self.key, signature: signature, rawText: rawText, id: id,
                                       production: production, expecting: expecting)
    }

    func disk() async throws -> VCDisk { try await VCFixture.disk(location) }

    /// The test-level contract of SPEC row VA3: canonical document and receipt agree, or the
    /// backend refuses further mutation as indeterminate.
    func assertAgreeOrLatched(_ label: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
        let disk = try await self.disk()
        let live = store.verifiedAnnotationAudit.records.map(\.operationID)
        if store.verifiedCommitLatch != nil {
            // Latched: further verified writes must be refused as recoverable-only.
            let next = try request(name: "after-latch-\(UUID().uuidString.prefix(4))", id: UUID())
            let outcome = await session.commitVerifiedAnnotation(next)
            XCTAssertEqual(outcome.refusalCode, .recoveryRequired, "\(label) \(outcome.description)", file: file, line: line)
            return
        }
        XCTAssertEqual(Set(disk.operationIDs), Set(live), "\(label) disk and live receipts disagree", file: file, line: line)
        let diskName = disk.overrides[key]?.customName, liveName = store.snapshot.addressOverrides[key]?.customName
        if diskName != liveName {
            XCTAssertTrue(store.hasUnsavedChanges, "\(label) live differs from disk without being dirty", file: file, line: line)
        }
    }

    /// The package on disk is self-consistent: the receipt is present exactly when the edit is.
    func assertDiskSelfConsistent(operationID: UUID, name: String = "verified-name",
                                  file: StaticString = #filePath, line: UInt = #line) async throws {
        let disk = try await self.disk()
        XCTAssertEqual(disk.operationIDs.contains(operationID), disk.overrides[key]?.customName == name,
                       "receipt and edit must be committed together", file: file, line: line)
    }
}

/// Runs a closure on the main actor from a non-main thread (publisher hooks run off-main while
/// the commit awaits on the main actor, so the main queue is free).
func vcOnMain(_ work: @MainActor () -> Void) {
    DispatchQueue.main.sync { MainActor.assumeIsolated { work() } }
}
