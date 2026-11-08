import Foundation

extension WorkspaceStore {
    /// Separate observation path: never infer committed state from the setter's return value.
    func readAnnotationProjection(at key: ImageAddress) throws -> NativeAnnotationProjection {
        try NativeAnnotationProjection(snapshot: snapshot, key: key)
    }

    /// MCP and attached MCP reach this same synchronous store owner via the scripting registry.
    /// Existing setters retain Undo, Navigator mirroring and edit-journal ownership. Compensating
    /// rollback is deliberately not described as isolated staging or atomic durable publication.
    func writeAnnotationWithReadback(
        at address: UInt64, in slot: ImageSlot, field: VerifiedAnnotationField, text: String
    ) -> ScriptValue {
        let key = ImageAddress(slot: slot, address: address)
        let requested = Self.normalizedOverrideText(text)
        var legacy: [String: ScriptValue] = ["ok": .bool(true), "address": .hex(address)]
        if field == .name { legacy["name"] = .string(text) }

        func reply(observed: String?, failure: VerifiedAnnotationFailure? = nil, legacyApplied: Bool = false) -> ScriptValue {
            var fields = legacy
            fields["requested"] = requested.map(ScriptValue.string) ?? .null
            fields["observed"] = observed.map(ScriptValue.string) ?? .null
            fields["verification"] = failure?.value ?? .string("candidateReadbackVerified")
            if failure != nil && !legacyApplied { fields["ok"] = .bool(false) }
            return .object(fields)
        }
        func commit(_ value: String?) {
            switch field {
            case .name: setCustomName(address, in: slot, name: value)
            case .comment: setCustomComment(address, in: slot, comment: value)
            }
        }

        // The legacy instruction/address route remains available and keeps its original limits.
        // Only function entries receive the new bounded readback assurance.
        guard snapshot.analysisBySlot[slot]?.functions.contains(where: { $0.startAddress == address }) == true else {
            commit(requested)
            let observed = field.value(in: snapshot.addressOverrides[key] ?? AddressOverride())
            return reply(observed: observed, failure: .init(code: .unsupportedTarget, stage: .normalize,
                recoveryHint: "Legacy address edit applied. Use a function entry for verified annotation readback."), legacyApplied: true)
        }
        guard (requested?.utf8.count ?? 0) <= field.maximumUTF8Bytes else {
            return reply(observed: field.value(in: snapshot.addressOverrides[key] ?? AddressOverride()),
                failure: .init(code: .valueTooLarge, stage: .normalize,
                    recoveryHint: "Shorten the normalized \(field.rawValue) to at most \(field.maximumUTF8Bytes) UTF-8 bytes; no edit was applied."))
        }
        do { try stageVerifiedAnnotation(at: key, field: field, requested: requested) }
        catch {
            let code: VerifiedAnnotationFailure.Code
            if error is CancellationError { code = .cancelled }
            else if let failure = error as? VerifiedCandidateError { code = failure.code }
            else if case VAVerificationError.candidateMismatch = error { code = .candidateMismatch }
            else { code = .measurementFailed }
            return reply(observed: field.value(in: snapshot.addressOverrides[key] ?? AddressOverride()),
                failure: .init(code: code, stage: .candidate,
                    recoveryHint: "Private candidate refused; no live edit, journal record or Undo entry was made. Inspect the candidate failure before retrying."))
        }
        let before: NativeAnnotationProjection
        do { before = try readAnnotationProjection(at: key) }
        catch {
            return reply(observed: field.value(in: snapshot.addressOverrides[key] ?? AddressOverride()),
                failure: .init(code: .projectionUnavailable, stage: .protectedFields,
                    recoveryHint: "Protected state could not be captured; inspect the workspace before retrying. No edit was applied."))
        }

        // One enclosing group prevents Undo from exposing the failed value after compensation.
        // A window's event group already provides it. Match applyOverride's owner rule so
        // the action name is not stranded in an extra nested group when groupsByEvent is true.
        let manager = undoManager
        let needsExplicitGroup = !manager.groupsByEvent
        if needsExplicitGroup { manager.beginUndoGrouping() }
        defer {
            manager.setActionName(field == .name ? "Rename" : "Edit Comment")
            if needsExplicitGroup { manager.endUndoGrouping() }
        }
        let changed = field.value(in: before.target) != requested
        let journalSequence = editJournal?.appendedSequence
        commit(requested)
        var observed = field.value(in: snapshot.addressOverrides[key] ?? AddressOverride())
        do { try checkEditJournalFailure() }
        catch {
            // Keep the established journal failure contract: the edit is still in memory,
            // later writes are latched off, and the scripting owner reports the failed append.
            // Compensation is for a readback mismatch, not a substitute for durable recovery.
            return reply(observed: observed, failure: .init(code: .commitFailed, stage: .commit,
                recoveryHint: "The annotation is in memory but the edit journal failed. Save the workspace to keep the edit; do not retry the mutation automatically."))
        }
        var stage = VerifiedAnnotationFailure.Stage.readback
        var code = VerifiedAnnotationFailure.Code.projectionUnavailable
        do {
            var after = try readAnnotationProjection(at: key)
            #if DEBUG
            // Per-store explicit test seam; not configurable by a tool argument or environment.
            verifiedAnnotationReadbackTestHook?(&after)
            #endif
            observed = field.value(in: after.target)
            if after.mismatch(comparedTo: before, field: field, requested: requested) == nil, changed {
                if field == .name {
                    guard let mirror = navigatorState(for: slot),
                          Self.verifiedNameMirror(mirror, snapshot: snapshot, key: key, observed: observed) else {
                        throw VerifiedCandidateError(.expectedEffectMismatch)
                    }
                }
                guard hasUnsavedChanges, manager.canUndo else { throw VerifiedCandidateError(.expectedEffectMismatch) }
                if let sequence = journalSequence, let journal = editJournal {
                    guard sequence < UInt64.max, journal.appendedSequence == sequence + 1,
                          case .override(_, let recordSlot, let recordAddress, let value)? = journal.lastAppendedRecord,
                          recordSlot == slot.rawValue, recordAddress == address,
                          value == snapshot.addressOverrides[key] else { throw VerifiedCandidateError(.expectedEffectMismatch) }
                }
            }
            guard let mismatch = after.mismatch(comparedTo: before, field: field, requested: requested) else {
                return reply(observed: observed)
            }
            stage = mismatch
            code = .candidateMismatch
        } catch let failure as VerifiedCandidateError {
            code = failure.code
        } catch {
            // An unavailable independent capture must not grant a readback claim.
        }

        commit(field.value(in: before.target))
        // Bypass the injected observation when checking actual compensation.
        let restored = (try? readAnnotationProjection(at: key)) == before
        return reply(observed: observed, failure: .init(code: code, stage: stage,
            recoveryHint: restored
                ? "The prior annotation was restored. Inspect current state before retrying; no durable verification receipt was issued."
                : "The prior annotation was requested through the setter, but protected state differs or is unreadable. Stop edits and inspect the workspace; do not retry automatically.",
            restored: restored))
    }
}
