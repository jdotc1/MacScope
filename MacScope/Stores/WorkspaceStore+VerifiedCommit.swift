import Foundation

/// Candidate values that replace the live ones inside the shared package-payload builder.
/// Nothing here is applied to the live store; the builder only reads these values.
struct VerifiedPayloadSubstitution {
    /// Candidate snapshot whose `addressOverrides` already carry the staged edit.
    let snapshot: WorkspaceSnapshot
    /// Staged Navigator mirror for the target slot, if the edit changes one.
    let navigatorMirror: (slot: ImageSlot, store: NavigatorContractStore)?
    /// Candidate envelope (baseline plus the new record), validated against the owner.
    let audit: VerifiedAnnotationAuditEnvelope
}

/// Store-side snapshot taken at admission. Everything the commit and its reconciliation need
/// to decide deterministically is captured here, on the MainActor, before any suspension.
struct VerifiedCommitAdmission {
    let operationID: UUID
    let requestDigest: String
    let installationID: UUID
    let generation: WorkspaceDocumentMutationGeneration
    let baselineEnvelope: VerifiedAnnotationAuditEnvelope
    let baselineMeasurementDigest: String
    let baselineTarget: AddressOverride?
    let acceptedBaselineCount: UInt64
    let fence: VerifiedCommitFence
}

struct StagedVerifiedCommit {
    let admission: VerifiedCommitAdmission
    let record: VerifiedAnnotationAuditRecord
    let nextEnvelope: VerifiedAnnotationAuditEnvelope
    let candidate: NativeAnnotationCandidate?
    let target: ImageAddress?
    let fieldClass: VerifiedFieldClass?
    let requested: String?
    /// The one definition the type resolved to at stage time (addressType only; nil when clearing).
    /// The published readback's resolved leg must find this same definition.
    let resolvedType: TypeDefinition?
    /// Session mode only; nil for the headless journal commit.
    let payload: WorkspaceDocumentPackagePayload?
}

struct VerifiedInstallResult: Equatable {
    var replaced = false
    var auditInstalled = false
    var annotationInstalled = false
    var liveAdvanced = false
    var clean = false
    var journalDegraded = false
}

enum VerifiedCommitIdempotency { case fresh, exact, conflict }

extension WorkspaceStore {
    // MARK: Version token and idempotency

    /// Opaque native publication token: installation, mutation generation and the audit digest,
    /// so audit-only changes (a rejected receipt) move it exactly like annotation changes.
    func verifiedCommitVersionToken() -> String {
        let auditDigest = (try? VerifiedAnnotationAuditCodec.encode(verifiedAnnotationAudit))
            .map(VerifiedAnnotationAuditCodec.sha256Hex) ?? "unencodable"
        let text = "\(documentInstallationID.uuidString)|\(mutationGeneration.rawValue)|\(auditDigest)"
        return VerifiedAnnotationAuditCodec.sha256Hex(Data(text.utf8))
    }

    func verifiedCommitIdempotency(for request: VerifiedAnnotationCommitRequest) -> VerifiedCommitIdempotency {
        guard let record = verifiedAnnotationAudit.records.first(where: { $0.operationID == request.operationID }) else {
            return .fresh
        }
        return record.body.requestDigest == request.receipt.requestDigest ? .exact : .conflict
    }

    func verifiedCommitExistingSnapshot(for request: VerifiedAnnotationCommitRequest) -> VABackendSnapshot {
        VABackendSnapshot(state: request.state, version: verifiedCommitVersionToken())
    }

    // MARK: Admission (CAS-A)

    /// Synchronous, before any suspension. Installs the fence and the exclusive in-flight marker.
    func beginVerifiedCommit(
        _ request: VerifiedAnnotationCommitRequest
    ) -> Result<VerifiedCommitAdmission, VerifiedAnnotationCommitRefusal> {
        guard verifiedCommitLatch == nil else { return .failure(.init(.recoveryRequired)) }
        guard activeVerifiedCommit == nil else { return .failure(.init(.writeBusy, "verified-commit-active")) }
        do { try checkEditJournalFailure() } catch { return .failure(.init(.journalFailed)) }
        guard verifiedCommitVersionToken() == request.expectingVersion else {
            return .failure(.init(.staleVersion))
        }
        let digest: String
        do {
            digest = try NativeCandidateMeasurement(snapshot: snapshot, overrides: snapshot.addressOverrides).digest
        } catch {
            return .failure(.init(.stageFailed, "baseline-measurement"))
        }
        let fence = VerifiedCommitFence()
        let accepted = verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count
        let admission = VerifiedCommitAdmission(
            operationID: request.operationID, requestDigest: request.receipt.requestDigest,
            installationID: documentInstallationID, generation: mutationGeneration,
            baselineEnvelope: verifiedAnnotationAudit, baselineMeasurementDigest: digest,
            baselineTarget: request.target.flatMap { snapshot.addressOverrides[$0] },
            acceptedBaselineCount: UInt64(accepted), fence: fence)
        verifiedCommitFence = fence
        activeVerifiedCommit = admission
        return .success(admission)
    }

    func endVerifiedCommit(_ admission: VerifiedCommitAdmission) {
        admission.fence.finish()
        if verifiedCommitFence === admission.fence { verifiedCommitFence = nil }
        if activeVerifiedCommit?.operationID == admission.operationID { activeVerifiedCommit = nil }
    }

    // MARK: Candidate preparation (no live mutation)

    func prepareVerifiedCommit(
        _ request: VerifiedAnnotationCommitRequest,
        admission: VerifiedCommitAdmission,
        buildPayload: Bool
    ) throws -> StagedVerifiedCommit {
        let receipt = request.receipt
        guard request.state.receipts.last == receipt else {
            throw VerifiedAnnotationCommitRefusal(.invalidReceipt, "receipt-not-last-in-state")
        }
        let wantsEdit = request.isAccepted
        guard wantsEdit == (request.target != nil && request.fieldClass != nil),
              wantsEdit == (receipt.after != nil) else {
            throw VerifiedAnnotationCommitRefusal(.invalidReceipt, "decision-shape")
        }
        if wantsEdit, let target = request.target, let fieldClass = request.fieldClass {
            let edit = receipt.request.edits.first
            let kind = edit?.kind
            let typed = fieldClass == .addressType || fieldClass == .functionSignature
                || kind == .addressType || kind == .functionPrototype
            if typed {
                // The Core edit, the declared class, the target and the value must all name the same edit,
                // so a typed audit record can never describe a different override change.
                guard receipt.request.edits.count == 1, kind == fieldClass.editKind,
                      edit?.target.function == VAAddress64(target.address),
                      edit?.value == request.requested else {
                    throw VerifiedAnnotationCommitRefusal(.invalidReceipt, "field-class-edit")
                }
            }
            if fieldClass == .functionSignature, let requested = request.requested {
                // The requested value must be canonical signature text. `decodeSignature` already enforces canonical form
                // (VerifiedFieldClass.swift:153); the equality below is defence in depth, because the published raw-leg
                // readback compares the stored canonical text with `requested` itself.
                guard let decoded = try? VerifiedFieldCodec.decodeSignature(requested),
                      (try? VerifiedFieldCodec.canonicalSignature(decoded)) == requested else {
                    throw VerifiedAnnotationCommitRefusal(.invalidReceipt, "signature-value")
                }
                // An all-unspecified signature has no persisted payload (`hasPersistedPayload`,
                // Models/AnalysisModels+Overrides.swift:301): the package writer would prune it, so it can never read
                // back. A quarantine-only signature has a payload but no analysis effect and stays committable.
                // The effective-leg no-effect fallback in `publishedReadbackMismatch` is kept as defence in depth.
                guard decoded.hasPersistedPayload else {
                    throw VerifiedAnnotationCommitRefusal(.invalidReceipt, "signature-no-effect")
                }
            }
        }
        let record: VerifiedAnnotationAuditRecord
        let nextEnvelope: VerifiedAnnotationAuditEnvelope
        do {
            record = try VerifiedAnnotationAuditRecord(
                receipt: receipt, nativeEvidenceLinks: request.nativeEvidenceLinks)
            nextEnvelope = try admission.baselineEnvelope.appending(
                record, workspaceID: workspaceID, documentID: documentID)
        } catch {
            throw VerifiedAnnotationCommitRefusal(.invalidReceipt, "audit-record")
        }
        func stamp(_ snap: WorkspaceSnapshot, revision: UInt64) throws -> VAProjectionStamp {
            try request.projector.stamp(
                workspaceID: workspaceID, documentID: documentID,
                installationID: admission.installationID, snapshot: snap, revision: revision)
        }
        do {
            guard try stamp(snapshot, revision: admission.acceptedBaselineCount) == receipt.before else {
                throw VerifiedAnnotationCommitRefusal(.projectionMismatch, "before-stamp")
            }
        } catch let refusal as VerifiedAnnotationCommitRefusal {
            throw refusal
        } catch {
            throw VerifiedAnnotationCommitRefusal(.projectionMismatch, "before-stamp-unavailable")
        }
        var candidate: NativeAnnotationCandidate?
        var candidateSnapshot = snapshot
        if wantsEdit, let target = request.target, let fieldClass = request.fieldClass {
            do {
                let staged: NativeAnnotationCandidate
                if let field = fieldClass.annotationField {
                    staged = try stageVerifiedAnnotation(at: target, field: field, requested: request.requested)
                } else if fieldClass == .functionSignature {
                    // rowTokens are not carried through the commit path: staging gets the decoded canonical value.
                    staged = try stageVerifiedSignature(
                        at: target, requested: try request.requested.map(VerifiedFieldCodec.decodeSignature))
                } else {
                    staged = try stageVerifiedType(at: target, requested: request.requested)
                }
                candidate = staged
                candidateSnapshot = staged.snapshot
                candidateSnapshot.addressOverrides = staged.overrides
            } catch let error as VerifiedCandidateError {
                throw VerifiedAnnotationCommitRefusal(.candidateRejected, error.code.rawValue)
            } catch is CancellationError {
                throw VerifiedAnnotationCommitRefusal(.cancelled)
            } catch {
                throw VerifiedAnnotationCommitRefusal(.stageFailed, "candidate")
            }
            do {
                guard try stamp(candidateSnapshot, revision: admission.acceptedBaselineCount + 1) == receipt.after else {
                    throw VerifiedAnnotationCommitRefusal(.projectionMismatch, "after-stamp")
                }
            } catch let refusal as VerifiedAnnotationCommitRefusal {
                throw refusal
            } catch {
                throw VerifiedAnnotationCommitRefusal(.projectionMismatch, "after-stamp-unavailable")
            }
        }
        var payload: WorkspaceDocumentPackagePayload?
        if buildPayload {
            let substitution = VerifiedPayloadSubstitution(
                snapshot: candidateSnapshot,
                navigatorMirror: candidate.flatMap { c in request.target.map { ($0.slot, c.mirror) } },
                audit: nextEnvelope)
            do {
                payload = try buildPackagePayload(substitution: substitution)
            } catch is CancellationError {
                throw VerifiedAnnotationCommitRefusal(.cancelled)
            } catch {
                throw VerifiedAnnotationCommitRefusal(.stageFailed, "payload-capture")
            }
            guard payload?.capturedMutationGeneration == admission.generation,
                  mutationGeneration == admission.generation,
                  documentInstallationID == admission.installationID else {
                throw VerifiedAnnotationCommitRefusal(.liveFenceRevoked, "capture-generation")
            }
        }
        return StagedVerifiedCommit(
            admission: admission, record: record, nextEnvelope: nextEnvelope, candidate: candidate,
            target: request.target, fieldClass: request.fieldClass, requested: request.requested,
            resolvedType: request.target.flatMap { candidateSnapshot.appliedType(at: $0) }, payload: payload)
    }

    // MARK: Published readback

    /// Independent readback through the real package reader. `exactEnvelope` is the post-publish
    /// check (the package must carry exactly baseline plus the record); reconciliation only needs
    /// the record to be present with identical bytes.
    func verifyPublishedVerifiedCommit(
        _ package: WorkspaceDocumentValidatedPackage,
        staged: StagedVerifiedCommit,
        exactEnvelope: Bool
    ) -> Bool {
        publishedReadbackMismatch(package, staged: staged, exactEnvelope: exactEnvelope) == nil
    }

    /// The stage of the first readback leg that disagrees, or nil when every leg agrees.
    /// `content` is the envelope or (name/comment) field leg, exactly as before. For `addressType` the
    /// two legs are separate: `content:raw-leg` (the override's `appliedTypeName`) and
    /// `content:resolved-leg` (`appliedType(at:)` returns the one definition resolved at stage time).
    /// Observed is the raw override plus the resolved type only. Pseudocode is never read: a type change
    /// retriggers the native decompiler, and its output change is expected collateral, not a mismatch.
    /// For `functionSignature` (S6b) the legs are `content:raw-leg` (canonical `override.signature` equals the
    /// request) and `content:effective-leg` (canonical `functionSignatureOverrides(in:)[address]` equals the request,
    /// or the imported prototype when clearing). `ownReturnAuthorityFile` is session-only and never read. The
    /// package reader's `analysisRepairs` pass (`WorkspaceAnalysisIntegrity.repair`) never touches address overrides,
    /// and the snapshot compared here is the repaired one, so any repair that changed a signature would be a
    /// raw-leg mismatch.
    /// `mutateReadbackSnapshot` is a test seam applied to the package-read snapshot only.
    func publishedReadbackMismatch(
        _ package: WorkspaceDocumentValidatedPackage,
        staged: StagedVerifiedCommit,
        exactEnvelope: Bool,
        mutateReadbackSnapshot: (@MainActor (inout WorkspaceSnapshot) -> Void)? = nil
    ) -> String? {
        let envelopeMismatch = "content"
        // The reader already validated these bytes; revalidating them here re-decodes the whole package.
        let validated = package.validatedContents?.contents ?? (try? MacScopeDocumentPackage.validatedContents(
            manifestData: package.manifestData,
            attachmentsByBinaryID: package.attachmentsByBinaryID,
            reconstructionState: package.reconstructionState,
            instructionSidecarData: package.instructionSidecarData
        ))
        guard let contents = validated,
              let envelope = contents.manifest.verifiedAnnotationAudit else { return envelopeMismatch }
        if exactEnvelope {
            guard envelope == staged.nextEnvelope else { return envelopeMismatch }
        } else {
            guard envelope.records.first(where: { $0.operationID == staged.record.operationID })?.digest
                    == staged.record.digest else { return envelopeMismatch }
        }
        if exactEnvelope, let key = staged.target, let fieldClass = staged.fieldClass {
            var read = contents.snapshot
            mutateReadbackSnapshot?(&read)
            let isType = fieldClass == .addressType
            let isSignature = fieldClass == .functionSignature
            guard fieldClass.value(in: read.addressOverrides[key] ?? AddressOverride()) == staged.requested else {
                return (isType || isSignature) ? "content:raw-leg" : envelopeMismatch
            }
            if isType {
                let resolved = read.appliedType(at: key)
                let agrees: Bool
                if let requested = staged.requested {
                    agrees = resolved != nil && resolved?.name == requested
                        && resolved?.id == staged.resolvedType?.id
                        && read.typeDefinitions.filter { $0.name == requested }.count == 1
                } else {
                    agrees = resolved == nil && staged.resolvedType == nil
                }
                guard agrees else { return "content:resolved-leg" }
            }
            if isSignature {
                // Effective leg (S6b): the merged view the decompiler consumes. It folds imported prototypes under
                // the authoritative override, so a clear must fall back to the canonical imported prototype (or nil).
                let observed = Self.canonicalSignatureText(read.functionSignatureOverrides(in: key.slot)[key.address])
                let requested = staged.requested.flatMap { try? VerifiedFieldCodec.decodeSignature($0) }
                let expected: String?
                if let requested, requested.hasAnalysisEffect {
                    expected = Self.canonicalSignatureText(requested)
                } else {
                    // Clearing, or a signature with no analysis effect (quarantine only): the override does not
                    // reach the effective view, so the stage-time imported prototype is what shows through.
                    let imported = staged.candidate?.snapshot.importedPrototypes[key].flatMap { $0.hasAnalysisEffect ? $0 : nil }
                    expected = Self.canonicalSignatureText(imported)
                }
                guard observed == expected else { return "content:effective-leg" }
            }
        }
        return nil
    }

    /// Canonical text of a signature for readback comparison; an uncanonicalisable value maps to a string no
    /// valid canonical text equals (the same rule as `VerifiedFieldClass.value(in:)`).
    static func canonicalSignatureText(_ signature: FunctionSignatureOverride?) -> String? {
        var override = AddressOverride()
        override.signature = signature
        return VerifiedFieldClass.functionSignature.value(in: override)
    }

    /// True iff the package carries this operation's record (any envelope shape that validates).
    func publishedPackageContainsVerifiedOperation(
        _ package: WorkspaceDocumentValidatedPackage, operationID: UUID
    ) -> Bool? {
        guard let contents = try? MacScopeDocumentPackage.validatedContents(
            manifestData: package.manifestData,
            attachmentsByBinaryID: package.attachmentsByBinaryID,
            reconstructionState: package.reconstructionState,
            instructionSidecarData: package.instructionSidecarData
        ) else { return nil }
        return contents.manifest.verifiedAnnotationAudit?.records.contains { $0.operationID == operationID } ?? false
    }

    // MARK: Install (CAS-C): one synchronous MainActor step

    /// `headless`: the single combined journal record already holds the override, so the install
    /// must not append a second one, and the document stays dirty (the package is saved later).
    func installCommittedVerifiedAnnotation(
        _ staged: StagedVerifiedCommit, headless: Bool = false
    ) -> VerifiedInstallResult {
        let disposition: OverrideJournalDisposition = headless ? .alreadyJournaled : .append
        let admission = staged.admission
        _ = admission.fence.beginInstall()
        defer { admission.fence.finish() }
        var result = VerifiedInstallResult()
        guard documentInstallationID == admission.installationID else {
            result.replaced = true
            return result
        }
        var advanced = mutationGeneration != admission.generation
        if !advanced {
            let live = try? NativeCandidateMeasurement(snapshot: snapshot, overrides: snapshot.addressOverrides).digest
            advanced = live != admission.baselineMeasurementDigest
        }
        result.liveAdvanced = advanced

        // History is never lost: the audit record is always installed.
        let merged: VerifiedAnnotationAuditEnvelope?
        if verifiedAnnotationAudit.records.contains(where: { $0.operationID == staged.record.operationID }) {
            merged = verifiedAnnotationAudit
        } else {
            merged = try? verifiedAnnotationAudit.appending(
                staged.record, workspaceID: workspaceID, documentID: documentID)
        }
        guard let merged else { return result }
        installVerifiedAuditEnvelope(merged)
        result.auditInstalled = true

        if let key = staged.target, let fieldClass = staged.fieldClass, let candidate = staged.candidate {
            if !advanced {
                applyOverride(key, candidate.overrides[key], actionName: "Verified Annotation", journal: disposition)
                result.annotationInstalled = true
            } else {
                // Key-level CAS: the later manual value of the same field wins.
                let live = snapshot.addressOverrides[key] ?? AddressOverride()
                let base = admission.baselineTarget ?? AddressOverride()
                if fieldClass.value(in: live) == fieldClass.value(in: base) {
                    var edited = live
                    fieldClass.set(staged.requested, in: &edited)
                    applyOverride(key, edited, actionName: "Verified Annotation", journal: disposition)
                    result.annotationInstalled = true
                }
            }
        }
        if !advanced && !headless {
            finalizeVerifiedPublicationClean()
            result.clean = !hasUnsavedChanges
        }
        do { try checkEditJournalFailure() } catch { result.journalDegraded = true }
        return result
    }

    /// Re-reads the committed live state through the projector. Only a clean (non-advanced)
    /// install can prove `live == receipt`.
    func committedBackendSnapshot(
        for request: VerifiedAnnotationCommitRequest, staged: StagedVerifiedCommit
    ) -> VABackendSnapshot? {
        guard verifiedAnnotationAudit.records.contains(where: { $0.digest == staged.record.digest }) else { return nil }
        let accepted = verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count
        guard let live = try? request.projector.stamp(
            workspaceID: workspaceID, documentID: documentID, installationID: documentInstallationID,
            snapshot: snapshot, revision: UInt64(accepted)) else { return nil }
        let expected = request.isAccepted ? request.receipt.after : request.receipt.before
        guard live == expected else { return nil }
        return VABackendSnapshot(state: request.state, version: verifiedCommitVersionToken())
    }
}

extension WorkspaceStore {
    /// Headless commit: no document session exists, so the R2 edit journal is the commit point.
    /// One synchronous MainActor turn with no suspension: the version compare, the candidate, the
    /// single combined journal line (override plus audit record) and the live install cannot be
    /// interleaved with any other mutation, so the compare is also the final compare.
    func commitVerifiedAnnotationHeadless(
        _ request: VerifiedAnnotationCommitRequest
    ) -> VerifiedAnnotationCommitOutcome {
        typealias Refusal = VerifiedAnnotationCommitRefusal
        guard !hasBoundDocumentSession else { return .refused(Refusal(.notHeadless)) }
        switch verifiedCommitIdempotency(for: request) {
        case .exact: return .existing(verifiedCommitExistingSnapshot(for: request))
        case .conflict: return .refused(Refusal(.idempotencyConflict))
        case .fresh: break
        }
        guard verifiedCommitLatch == nil else { return .refused(Refusal(.recoveryRequired)) }
        guard let journal = editJournal else { return .refused(Refusal(.headlessJournalRequired)) }
        guard journal.observedHealth == .healthy else { return .refused(Refusal(.journalFailed)) }
        let admission: VerifiedCommitAdmission
        switch beginVerifiedCommit(request) {
        case .failure(let refusal): return .refused(refusal)
        case .success(let admitted): admission = admitted
        }
        defer { endVerifiedCommit(admission) }
        let staged: StagedVerifiedCommit
        do {
            staged = try prepareVerifiedCommit(request, admission: admission, buildPayload: false)
        } catch let refusal as Refusal {
            return .refused(refusal)
        } catch {
            return .refused(Refusal(.stageFailed))
        }

        func latch(
            _ code: VerifiedAnnotationCommitIndeterminate.Code, _ detail: String?
        ) -> VerifiedAnnotationCommitOutcome {
            verifiedCommitLatch = VerifiedCommitLatch(
                operationID: request.operationID, requestDigest: request.receipt.requestDigest,
                reason: code.rawValue, isHeadless: true, expectedVersion: nil)
            verifiedCommitRecovery = staged
            return .indeterminate(VerifiedAnnotationCommitIndeterminate(code, detail))
        }

        // Commit point: ONE fsync'd line holding the override change and the audit record.
        let key = request.target
        let before = journal.appendedSequence
        journal.appendVerifiedAnnotation(
            slot: key?.slot.rawValue ?? -1, address: key?.address ?? 0,
            changesOverride: staged.candidate != nil,
            value: key.flatMap { staged.candidate?.overrides[$0] }, audit: staged.record)
        guard journal.observedHealth == .healthy, journal.appendedSequence == before + 1 else {
            // The writer cannot tell "not written" from "written, fsync failed".
            return latch(.journalAppendUncertain, "journal-append")
        }
        #if DEBUG
        do { try verifiedHeadlessBeforeInstallHookForTesting?() } catch {
            return latch(.committedLiveNotInstalled, "install-hook")
        }
        #endif
        let install = installCommittedVerifiedAnnotation(staged, headless: true)
        guard install.auditInstalled, !install.replaced else {
            return latch(.committedLiveNotInstalled, "audit-install")
        }
        guard let snapshot = committedBackendSnapshot(for: request, staged: staged) else {
            return latch(.committedLiveNotInstalled, "post-install-stamp")
        }
        return .committed(snapshot, VerifiedAnnotationCommitInfo(
            operationID: request.operationID, annotationInstalled: install.annotationInstalled,
            liveAdvanced: false, journalDegraded: install.journalDegraded))
    }
}
