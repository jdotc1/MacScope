import Foundation

struct VerifiedCandidateError: Error {
    let code: VerifiedAnnotationFailure.Code
    init(_ code: VerifiedAnnotationFailure.Code) { self.code = code }
}

/// Transient value-only stage. `snapshot` retains the original generation; the private
/// annotation map is separate so staging cannot invalidate the live analysis memo.
struct NativeAnnotationCandidate {
    var snapshot: WorkspaceSnapshot
    var overrides: [ImageAddress: AddressOverride]
    var revision: UInt64
    var installationID: UUID
    var workspaceID: UUID
    var documentID: UUID
    var fences: [ImageSlot: NavigatorLandingFence]
    var generations: [ImageSlot: NavigatorGeneration]
    var mirror: NavigatorContractStore
    var measuredMembers = NativeCandidateMeasurement.requiredMembers
}

/// Every required owner is measured independently. A missing measurement is a refusal,
/// including when both before/after projections happen to omit the same member.
struct NativeCandidateMeasurement: Equatable {
    static let requiredMembers: Set<String> = [
        "overrides", "binaries", "fingerprints", "types", "prototypes", "generation",
        "manualXRefs", "bookmarks", "segments", "breakpoints", "launchProfiles", "watches", "sourceLinks"
    ]
    let members: [String: Data]
    var digest: String { get throws { VASHA256Digest.hex(try VACanonicalJSON.encode(members)) } }

    init(snapshot: WorkspaceSnapshot, overrides: [ImageAddress: AddressOverride],
         measuredMembers: Set<String> = requiredMembers) throws {
        guard measuredMembers == Self.requiredMembers else { throw VerifiedCandidateError(.measurementFailed) }
        struct OverrideValue: Encodable {
            let slot: Int
            let address: UInt64
            let value: AddressOverride
            let authority: String?
        }
        struct Fingerprint: Encodable {
            let slot: Int
            let value: AnalysisInputFingerprint?
        }
        var result: [String: Data] = [:]
        func add<T: Encodable>(_ name: String, _ value: T) throws {
            result[name] = try VACanonicalJSON.encode(value)
        }
        try add("overrides", overrides.sorted { ($0.key.slot.rawValue, $0.key.address) < ($1.key.slot.rawValue, $1.key.address) }
            .map { OverrideValue(slot: $0.key.slot.rawValue, address: $0.key.address,
                                 value: $0.value, authority: $0.value.ownReturnAuthorityFile) })
        try add("binaries", snapshot.binaries)
        try add("fingerprints", snapshot.analysisBySlot.sorted { $0.key < $1.key }
            .map { Fingerprint(slot: $0.key.rawValue, value: $0.value.analysisInputFingerprint) })
        try add("generation", snapshot.analysisGenerationID)
        try add("types", snapshot.typeDefinitions)
        try add("prototypes", ImportedPrototypeEntry.entries(from: snapshot.importedPrototypes))
        try add("manualXRefs", snapshot.manualXRefs)
        try add("bookmarks", snapshot.bookmarks)
        try add("segments", snapshot.segmentOverrides)
        try add("breakpoints", snapshot.logicalBreakpointCatalog)
        result["launchProfiles"] = try DebuggerLaunchProfileCanonicalCodec.encodeCatalog(snapshot.launchProfileCatalog)
        try add("watches", snapshot.savedWatchCatalog)
        try add("sourceLinks", snapshot.sourceLinkState)
        guard Set(result.keys) == Self.requiredMembers else { throw VerifiedCandidateError(.measurementFailed) }
        members = result
    }
}

private struct NativeSupportedAnnotations: Equatable {
    struct Value: Equatable {
        let key: ImageAddress
        var name: String?
        var comment: String?
        /// Only populated when `includesType` is set (the type class); nil otherwise, so name/comment
        /// staging compares exactly what it compared before S3.
        var type: String? = nil
        /// Canonical signature (`VerifiedFieldCodec.canonicalSignature`: rowToken and provenance dropped,
        /// rows in order). Only populated when `includesSignature` is set.
        var signature: String? = nil
    }
    let revision: UInt64
    let installationID: UUID
    let generation: UUID
    let binaries: [BinaryImage]
    var values: [Value]

    init(_ candidate: NativeAnnotationCandidate, includesType: Bool = false, includesSignature: Bool = false) throws {
        revision = candidate.revision
        installationID = candidate.installationID
        generation = candidate.snapshot.analysisGenerationID
        binaries = candidate.snapshot.binaries
        // Empty name/comment rows carry no portable annotation; native membership and all
        // other override fields are checked separately by NativeCandidateMeasurement.
        values = try candidate.overrides.compactMap { key, value in
            let type = includesType ? value.appliedTypeName.flatMap { $0.isEmpty ? nil : $0 } : nil
            let signature = try includesSignature ? value.signature.map(VerifiedFieldCodec.canonicalSignature) : nil
            guard value.customName != nil || value.customComment != nil || type != nil || signature != nil else { return nil }
            return Value(key: key, name: value.customName, comment: value.customComment, type: type, signature: signature)
        }.sorted { ($0.key.slot.rawValue, $0.key.address) < ($1.key.slot.rawValue, $1.key.address) }
    }
}

/// The field one staging pass writes: the legacy name/comment accessor, the S3 type class, or the S6a
/// signature class. The signature case carries the requested value itself (rowTokens included) so the
/// staged override holds exactly what the caller asked for; comparisons use the canonical string.
private enum NativeStagedField: Equatable {
    case annotation(VerifiedAnnotationField)
    case addressType
    case functionSignature(FunctionSignatureOverride?)

    /// The comparable text of the field. For a signature this is the canonical form, so rowToken and
    /// provenance never take part (VA-SCOPE ruling 7). Throws only if a signature cannot be canonicalised.
    func value(in override: AddressOverride) throws -> String? {
        switch self {
        case .annotation(let field): return field.value(in: override)
        case .addressType: return override.appliedTypeName
        case .functionSignature: return try override.signature.map(VerifiedFieldCodec.canonicalSignature)
        }
    }

    /// Writes the requested value. The signature case ignores `value` and writes its carried signature;
    /// the `didSet` on `AddressOverride.signature` then resets the session authority if it changed.
    func set(_ value: String?, in override: inout AddressOverride) {
        switch self {
        case .annotation(let field): field.set(value, in: &override)
        case .addressType: override.appliedTypeName = value
        case .functionSignature(let signature): override.signature = signature
        }
    }

    /// Resets exactly the field this class owns to its baseline. For a signature, the session-only
    /// `ownReturnAuthorityFile` is reset with it only when the signature actually changed and the candidate
    /// holds the `didSet` reset (nil); any other authority value is left in place so it shows as drift (T10).
    func restore(from baseline: AddressOverride, in override: inout AddressOverride) {
        switch self {
        case .annotation, .addressType:
            set(try? value(in: baseline), in: &override)
        case .functionSignature:
            let authority = override.ownReturnAuthorityFile
            let changed = override.signature != baseline.signature
            override.signature = baseline.signature
            override.ownReturnAuthorityFile = (changed && authority == nil) ? baseline.ownReturnAuthorityFile : authority
        }
    }
}

extension WorkspaceStore {
    /// No setter, Undo group, journal append or dirty mutation may occur before this returns.
    @discardableResult
    func stageVerifiedAnnotation(at key: ImageAddress, field: VerifiedAnnotationField, requested: String?) throws -> NativeAnnotationCandidate {
        try stageVerifiedField(at: key, field: .annotation(field), requested: requested)
    }

    /// Type class (VA-SCOPE S3): stages `appliedTypeName` on an isolated candidate. nil clears.
    /// Typed refusals before any candidate exists: `invalidTypeName`, `addressOutsideSegments`,
    /// `functionEntryTarget`, `unresolvedType` (no definition has the name), `ambiguousType` (more than
    /// one does). No setter, Undo group, journal append or dirty mutation occurs.
    @discardableResult
    func stageVerifiedType(at key: ImageAddress, requested: String?) throws -> NativeAnnotationCandidate {
        try stageVerifiedField(at: key, field: .addressType, requested: requested)
    }

    /// Signature class (VA-SCOPE S6a): stages `AddressOverride.signature` on an isolated candidate. nil clears.
    /// Typed refusals before any candidate exists: `invalidSignature` (the value does not round-trip through
    /// `canonicalSignature`/`decodeSignature`), the target must be a function
    /// entry, otherwise `notFunctionEntry` (the opposite of the type class).
    ///
    /// "Observed equals requested" is compared by canonical signature: rowToken and provenance are dropped and
    /// rows are compared in order. Type names inside a signature are free text and are NOT required to resolve
    /// to a `TypeDefinition` (many are primitives with none): the verified claim is that the stored signature
    /// equals the requested one, not that its types exist (DESIGN Question 5, ruled in S6a). A rowToken-only
    /// change is a no-op for that comparison but still moves the protected override members, which the erase
    /// rule resets together with the session authority that the signature `didSet` clears.
    /// No setter, Undo group, journal append or dirty mutation occurs.
    @discardableResult
    func stageVerifiedSignature(at key: ImageAddress, requested: FunctionSignatureOverride?) throws -> NativeAnnotationCandidate {
        let text: String?
        if let requested {
            do {
                let canonical = try VerifiedFieldCodec.canonicalSignature(requested)
                guard try VerifiedFieldCodec.canonicalSignature(VerifiedFieldCodec.decodeSignature(canonical)) == canonical else {
                    throw VerifiedCandidateError(.invalidSignature)
                }
                text = canonical
            } catch is VerifiedFieldCodecError {
                throw VerifiedCandidateError(.invalidSignature)
            }
        } else {
            text = nil
        }
        guard NativeAddressFacts.isFunctionEntry(snapshot: snapshot, key: key) else {
            throw VerifiedCandidateError(.notFunctionEntry)
        }
        return try stageVerifiedField(at: key, field: .functionSignature(requested), requested: text)
    }

    private func stageVerifiedField(at key: ImageAddress, field: NativeStagedField, requested: String?) throws -> NativeAnnotationCandidate {
        try Task.checkCancellation()
        let includesType = field == .addressType
        let includesSignature: Bool
        if case .functionSignature = field { includesSignature = true } else { includesSignature = false }
        if includesType {
            if let requested {
                guard (try? VerifiedFieldCodec.canonicalTypeName(requested)) == requested else {
                    throw VerifiedCandidateError(.invalidTypeName)
                }
            }
            let entry = try NativeAddressFacts.entry(snapshot: snapshot, key: key)
            guard !entry.isFunctionEntry else { throw VerifiedCandidateError(.functionEntryTarget) }
            if let requested {
                switch snapshot.typeDefinitions.filter({ $0.name == requested }).count {
                case 0: throw VerifiedCandidateError(.unresolvedType)
                case 1: break
                default: throw VerifiedCandidateError(.ambiguousType)
                }
            }
        }
        let baseline = NativeAnnotationCandidate(snapshot: snapshot, overrides: snapshot.addressOverrides,
            revision: mutationGeneration.rawValue, installationID: documentInstallationID,
            workspaceID: workspaceID, documentID: documentID,
            fences: Dictionary(uniqueKeysWithValues: snapshot.binaries.map { ($0.slot, navigatorLandingFence(for: $0.slot)) }),
            generations: navigatorGenerations,
            mirror: navigatorState(for: key.slot) ?? NavigatorContractStore(toolchain: NavigatorStateBridge.pendingToolchain))
        let before = try NativeCandidateMeasurement(snapshot: baseline.snapshot, overrides: baseline.overrides)
        var candidate = baseline
        var target = candidate.overrides[key] ?? AddressOverride()
        field.set(requested, in: &target)
        candidate.overrides[key] = target.isEmpty ? nil : target
        candidate.mirror = try stagedAnalystMirror(for: key, previous: baseline.overrides[key], value: candidate.overrides[key])
        let expectedMirror = candidate.mirror
        #if DEBUG
        try verifiedAnnotationCandidateTestHook?(&candidate)
        #endif
        try Task.checkCancellation()

        // Use the package writer's actual override representation and reader map. No live
        // snapshot is serialized or mutated. Session-only authority stays in a separate copy.
        let partition = candidate.overrides.filter { $0.key.slot == key.slot }
        var bytes = try VACanonicalJSON.encode(WorkspacePackageAnalysis.entries(from: partition))
        #if DEBUG
        try verifiedAnnotationCandidateBytesTestHook?(&bytes)
        #endif
        let entries: [AddressOverrideEntry]
        do { entries = try JSONDecoder().decode([AddressOverrideEntry].self, from: bytes) }
        catch { throw VerifiedCandidateError(.measurementFailed) }
        let keys = entries.map { ImageAddress(slot: $0.imageSlot, address: $0.address) }
        guard Set(keys).count == keys.count, keys.allSatisfy({ $0.slot == key.slot }) else {
            throw VerifiedCandidateError(.unexpectedAnnotation)
        }
        var decoded = WorkspacePackageAnalysis.overrideMap(from: entries)
        for (address, value) in partition where value.ownReturnAuthorityFile != nil {
            guard decoded[address] != nil else { throw VerifiedCandidateError(.protectedFieldMismatch) }
            decoded[address]?.ownReturnAuthorityFile = value.ownReturnAuthorityFile
        }
        candidate.overrides = candidate.overrides.filter { $0.key.slot != key.slot }.merging(decoded) { _, new in new }
        guard try field.value(in: candidate.overrides[key] ?? AddressOverride()) == requested else {
            throw VerifiedCandidateError(.missingCandidateField)
        }
        guard candidate.revision == baseline.revision,
              candidate.installationID == baseline.installationID,
              candidate.workspaceID == baseline.workspaceID, candidate.documentID == baseline.documentID,
              candidate.fences == baseline.fences, candidate.generations == baseline.generations,
              candidate.snapshot.analysisGenerationID == baseline.snapshot.analysisGenerationID,
              candidate.snapshot.binaries == baseline.snapshot.binaries else {
            throw VerifiedCandidateError(.changedIdentity)
        }
        guard Set(candidate.overrides.keys).subtracting(baseline.overrides.keys).isSubset(of: [key]) else {
            throw VerifiedCandidateError(.unexpectedAnnotation)
        }
        let original = try NativeSupportedAnnotations(baseline, includesType: includesType, includesSignature: includesSignature)
        let supported = try NativeSupportedAnnotations(candidate, includesType: includesType, includesSignature: includesSignature)
        try VACandidateVerifier.verify(before: original, candidate: supported, requested: requested,
            observed: try field.value(in: candidate.overrides[key] ?? AddressOverride())) { normalized in
                let old = original.values.first(where: { $0.key == key })
                var restored = normalized.values.first(where: { $0.key == key })
                    ?? NativeSupportedAnnotations.Value(key: key, name: nil, comment: nil)
                switch field {
                case .annotation(.name): restored.name = old?.name
                case .annotation(.comment): restored.comment = old?.comment
                case .addressType: restored.type = old?.type
                case .functionSignature: restored.signature = old?.signature
                }
                normalized.values.removeAll { $0.key == key }
                if restored.name != nil || restored.comment != nil || restored.type != nil || restored.signature != nil {
                    normalized.values.append(restored)
                }
                normalized.values.sort { ($0.key.slot.rawValue, $0.key.address) < ($1.key.slot.rawValue, $1.key.address) }
            }
        // Erase precisely the allowed field; retain unexpected protected members even when
        // the baseline target was absent. Prune only the legitimate empty clear representation.
        var erased = candidate.overrides
        var restored = erased[key] ?? AddressOverride()
        field.restore(from: baseline.overrides[key] ?? AddressOverride(), in: &restored)
        erased[key] = restored.isEmpty && baseline.overrides[key] == nil ? nil : restored
        let measured = try NativeCandidateMeasurement(snapshot: candidate.snapshot, overrides: erased,
                                                       measuredMembers: candidate.measuredMembers)
        guard try measured.digest == before.digest else { throw VerifiedCandidateError(.protectedFieldMismatch) }
        guard candidate.mirror.state() == expectedMirror.state(),
              candidate.mirror.staleGeneration == expectedMirror.staleGeneration else {
            throw VerifiedCandidateError(.expectedEffectMismatch)
        }
        switch field {
        case .annotation(.name):
            guard Self.verifiedNameMirror(candidate.mirror, snapshot: candidate.snapshot, key: key, observed: requested) else {
                throw VerifiedCandidateError(.expectedEffectMismatch)
            }
        case .annotation(.comment):
            break
        case .addressType:
            guard Self.verifiedTypeMirror(candidate.mirror, snapshot: candidate.snapshot, key: key, observed: requested) else {
                throw VerifiedCandidateError(.expectedEffectMismatch)
            }
        case .functionSignature:
            // No Navigator predicate covers signatures (DESIGN 2.3); the effective-view leg is S6b's readback.
            break
        }
        // The live mirror owner also reconciles findings. This lane allows no finding
        // mutation: preflight that pure reconciliation against the staged mirror. Reuse
        // existing image identities only; never derive a new source-byte digest here.
        if !analystFindings.records.isEmpty {
            var support = AnalystFindingSupportSource()
            for binary in snapshot.binaries {
                guard let identity = navigatorGenerations[binary.slot]?.imageIdentity
                    ?? binary.artifactIdentity.map(NavigatorSubjectRef.imageRef) else {
                    throw VerifiedCandidateError(.measurementFailed)
                }
                support.imageIdentities[binary.slot] = identity
                support.stores[binary.slot] = navigatorState(for: binary.slot)
            }
            support.stores[key.slot] = candidate.mirror
            guard AnalystFindingSupport.staleMarks(in: analystFindings.records, touching: [key.slot], source: support).isEmpty else {
                throw VerifiedCandidateError(.expectedEffectMismatch)
            }
        }
        try Task.checkCancellation()
        // Synchronous MainActor staging cannot suspend, nevertheless bind the final owner cut.
        guard mutationGeneration.rawValue == baseline.revision, documentInstallationID == baseline.installationID,
              snapshot.analysisGenerationID == baseline.snapshot.analysisGenerationID,
              workspaceID == baseline.workspaceID, documentID == baseline.documentID,
              navigatorGenerations == baseline.generations,
              snapshot.binaries.allSatisfy({ navigatorLandingFence(for: $0.slot) == baseline.fences[$0.slot] }) else {
            throw VerifiedCandidateError(.changedIdentity)
        }
        return candidate
    }

    /// The `hasType` analogue of `verifiedNameMirror`: the highest-sequence live analyst `hasType`
    /// annotation for the address subject must equal the observed type, and clearing must leave none.
    static func verifiedTypeMirror(_ mirror: NavigatorContractStore, snapshot: WorkspaceSnapshot,
                                   key: ImageAddress, observed: String?) -> Bool {
        let subject = NavigatorSubjectRef.subject(kind: "address", ref: NavigatorSubjectRef.address(key.address),
                                                  identity: snapshot.binary(in: key.slot)?.artifactIdentity)
        let types = mirror.liveAnnotations().filter {
            $0.author == "analyst" && $0.subject == subject && $0.predicate == "hasType"
        }
        guard let observed else { return types.isEmpty }
        return types.max(by: { $0.seq < $1.seq })?.value == .string(observed)
    }

    static func verifiedNameMirror(_ mirror: NavigatorContractStore, snapshot: WorkspaceSnapshot,
                                   key: ImageAddress, observed: String?) -> Bool {
        let subject = NavigatorSubjectRef.subject(kind: "address", ref: NavigatorSubjectRef.address(key.address),
                                                  identity: snapshot.binary(in: key.slot)?.artifactIdentity)
        let names = mirror.liveAnnotations().filter {
            $0.author == "analyst" && $0.subject == subject && $0.predicate == "hasName"
        }
        // The contract retains earlier analyst annotations; the highest sequence is the
        // current analyst edit. Clearing must revert every live name for this subject.
        guard let observed else { return names.isEmpty }
        return names.max(by: { $0.seq < $1.seq })?.value == .string(observed)
    }
}
