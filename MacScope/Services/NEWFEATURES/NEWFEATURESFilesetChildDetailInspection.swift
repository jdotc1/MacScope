import Foundation
import NEWFEATURESCore

/// Owner-bound declaration inspection. Neither the DTO nor a child selector is authority.
@MainActor
enum NEWFEATURESFilesetChildDetailInspection {
    struct Limits: Sendable {
        var maximumImages = 256
        var maximumInputBytes = 64 * 1_024 * 1_024
        var maximumSerializedBytes = 2 * 1_024 * 1_024
        var maximumElapsedSeconds = 10
        var detail = MachOFilesetChildInspectionLimits()

        fileprivate func validatedDetail() throws -> MachOFilesetChildInspectionLimits {
            guard (1...256).contains(maximumImages),
                  (1...64 * 1_024 * 1_024).contains(maximumInputBytes),
                  (1...2 * 1_024 * 1_024).contains(maximumSerializedBytes),
                  (1...10).contains(maximumElapsedSeconds) else { throw Failure.invalidLimits }
            do { try detail.validate() } catch { throw Failure.invalidLimits }
            let index = detail.indexLimits, hard = MachOFilesetIndexLimits()
            for (value, ceiling) in [
                (index.maximumContainerBytes, hard.maximumContainerBytes),
                (index.maximumCommandBytes, hard.maximumCommandBytes),
                (index.maximumCommands, hard.maximumCommands),
                (index.maximumEntries, hard.maximumEntries),
                (index.maximumEntryIDBytes, hard.maximumEntryIDBytes),
                (index.maximumChildCommandBytes, hard.maximumChildCommandBytes),
                (index.maximumSegments, hard.maximumSegments),
                (index.maximumSections, hard.maximumSections),
                (index.maximumMappingComparisons, hard.maximumMappingComparisons),
                (index.maximumOutputBytes, hard.maximumOutputBytes)
            ] { guard value > 0, value <= ceiling else { throw Failure.invalidLimits } }
            var result = detail
            result.maximumInputBytes = min(result.maximumInputBytes, maximumInputBytes)
            result.maximumOutputBytes = min(result.maximumOutputBytes, maximumSerializedBytes)
            result.indexLimits.maximumContainerBytes = min(index.maximumContainerBytes, result.maximumInputBytes)
            result.indexLimits.maximumEntries = min(index.maximumEntries, 256)
            result.indexLimits.maximumEntryIDBytes = min(index.maximumEntryIDBytes, 256)
            result.indexLimits.maximumCommands = min(index.maximumCommands, 1_024)
            result.indexLimits.maximumCommandBytes = min(index.maximumCommandBytes, 1_024 * 1_024)
            result.indexLimits.maximumChildCommandBytes = min(index.maximumChildCommandBytes, 4 * 1_024 * 1_024)
            result.indexLimits.maximumSegments = min(index.maximumSegments, 1_024)
            result.indexLimits.maximumSections = min(index.maximumSections, 8_192)
            result.indexLimits.maximumMappingComparisons = min(index.maximumMappingComparisons, 65_536)
            result.indexLimits.maximumOutputBytes = min(index.maximumOutputBytes, maximumSerializedBytes)
            return result
        }
    }
    enum Failure: Error, Equatable { case invalidLimits, inputLimit, cancelled, timedOut, staleSource, outputLimit }
    enum AdmissionReason: String, Codable, Equatable, Sendable {
        case ownerUnavailable, artifactUnavailable, inputUnavailable, ownerMismatch
        case sliceCPU, headerUnavailable, headerCPU, selectorParentOrLength
    }
    enum Refusal: Codable, Equatable, Sendable {
        case admission(AdmissionReason)
        case selectorMismatch
        case detailLimit
        case detailMalformed(parentOffset: UInt64)
        case indexUnsupported(offset: UInt64)
        case indexMalformed(offset: UInt64)
        case indexLimit
        case indexIdentityMismatch
        case unexpected
    }
    struct Delivery: Codable, Sendable {
        enum Status: String, Codable, Equatable, Sendable { case inspected, refused }
        let image: NEWFEATURESImageKey
        let parent: MachOSliceArtifactIdentity?
        let selection: MachOFilesetIndex.Identity?
        let status: Status
        let detail: MachOFilesetChildInspection?
        let refusal: Refusal?
    }
    private struct WorkerInput: Sendable {
        let bytes: Data
        let parent: MachOSliceArtifactIdentity
        let image: NEWFEATURESImageKey
        let selection: MachOFilesetIndex.Identity
        let limits: MachOFilesetChildInspectionLimits
        let maximumSerializedBytes: Int
    }
    struct Prepared {
        fileprivate let envelope: NEWFEATURESResultEnvelope<Data>
        fileprivate let bridge: NEWFEATURESAdmissionBridge
        fileprivate let requireCurrent: @MainActor () throws -> Void
        fileprivate init(envelope: NEWFEATURESResultEnvelope<Data>, bridge: NEWFEATURESAdmissionBridge,
                         requireCurrent: @escaping @MainActor () throws -> Void) {
            self.envelope = envelope; self.bridge = bridge; self.requireCurrent = requireCurrent
        }
    }

    static func capture(slot: ImageSlot, store: WorkspaceStore, session: WorkspaceDocumentSession,
                        selecting: MachOFilesetIndex.Identity, limits: Limits = .init(),
                        now: @escaping @MainActor () -> ContinuousClock.Instant = { ContinuousClock().now },
                        isCancelled: @escaping @MainActor () -> Bool = { false }) async throws -> Prepared {
        let started = now()
        let detailLimits = try limits.validatedDetail()
        let deadline = started.advanced(by: .seconds(limits.maximumElapsedSeconds))
        func requireTime() throws {
            guard !Task.isCancelled, !isCancelled() else { throw Failure.cancelled }
            guard now() < deadline else { throw Failure.timedOut }
        }
        try requireTime()
        let snapshot = store.snapshot
        guard snapshot.binaries.count <= limits.maximumImages else { throw Failure.inputLimit }
        if let fingerprint = snapshot.analysis(in: slot)?.analysisInputFingerprint,
           fingerprint.facets.count > AnalysisFingerprintFacetKind.allCases.count { throw Failure.inputLimit }
        let bridge = NEWFEATURESAdmissionBridge(store: store, session: session)
        let admission = try bridge.admit(slot: slot)
        let image = admission.projection.image
        let revision = store.mutationGeneration
        let state = store.phase2ReadCurrentState(for: slot)
        let requireCurrent: @MainActor () throws -> Void = { [weak store, weak session] in
            try requireTime()
            guard let store, let session, !session.isClosedForWindowClose,
                  !session.isTerminationPreparationActive,
                  session.snapshot.documentID == store.documentID,
                  session.snapshot.workspaceID == store.workspaceID,
                  store.mutationGeneration == revision,
                  store.phase2ReadCurrentState(for: slot) == state else { throw Failure.staleSource }
            try bridge.revalidate(admission)
        }
        func finish(_ bytes: Data) throws -> Prepared {
            try requireCurrent()
            return Prepared(envelope: admission.retaining(bytes), bridge: bridge, requireCurrent: requireCurrent)
        }
        func refused(_ reason: AdmissionReason, parent: MachOSliceArtifactIdentity? = nil) throws -> Prepared {
            let value = Delivery(image: image, parent: parent, selection: nil, status: .refused,
                                 detail: nil, refusal: .admission(reason))
            return try finish(encode(value, maximum: limits.maximumSerializedBytes))
        }
        let owners = snapshot.binaries.filter { $0.slot == slot }
        guard owners.count == 1, let binary = owners.first,
              let analysis = snapshot.analysis(in: slot), let fingerprint = analysis.analysisInputFingerprint
        else { return try refused(.ownerUnavailable) }
        guard binary.artifactIntegrityState == .verified, let parent = binary.artifactIdentity else {
            return try refused(.artifactUnavailable)
        }
        guard !analysis.imageBytes.isEmpty, analysis.imageBytes.count <= detailLimits.maximumInputBytes else {
            return try refused(.inputUnavailable)
        }
        guard binary.id == image.binaryID, binary.slot.rawValue == image.slot,
              binary.architecture == image.architecture, binary.selectedSliceIndex == image.sliceIndex,
              fingerprint.imageSlot == slot, fingerprint.binaryID == binary.id,
              fingerprint.selectedSliceIndex == binary.selectedSliceIndex,
              fingerprint.artifactIdentity == parent, fingerprint.elfArchiveMemberIdentity == nil,
              binary.elfArchiveMemberIdentity == nil,
              fingerprint.imageBytesSHA256 == parent.selectedSliceSHA256,
              image.contentSHA256 == parent.selectedSliceSHA256,
              image.analysisInputFingerprintSHA256 == fingerprint.overallSHA256,
              fingerprint.imageByteCount == parent.selectedSliceByteCount,
              UInt64(analysis.imageBytes.count) == parent.selectedSliceByteCount else {
            return try refused(.ownerMismatch)
        }
        if let fact = binary.machOSelectedSliceFact {
            guard fact.cpuType == parent.rawCPUType, fact.cpuSubtype == parent.rawCPUSubtype,
                  fact.universalSliceIndex == binary.selectedSliceIndex else {
                return try refused(.sliceCPU)
            }
        }
        // Thin selected bytes retain their own header. Comparing it requires no content digest.
        // Retain the whole selected parent, never a hex window or inferred child slice.
        let bytes = analysis.imageBytes
        guard bytes.count >= 12 else { return try refused(.headerUnavailable) }
        func word(_ offset: Int) -> UInt32 {
            (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[bytes.startIndex + offset + $1]) << (8 * $1) }
        }
        if word(0) == MachOConstants.machMagic64 {
            guard Int32(bitPattern: word(4)) == parent.rawCPUType,
                  Int32(bitPattern: word(8)) == parent.rawCPUSubtype else {
                return try refused(.headerCPU)
            }
        } // Other container encodings retain the parser's explicit unsupported distinction.
        // Bounded prefix traversal rejects text without copying or scanning an arbitrary suffix.
        let nameLimit = detailLimits.indexLimits.maximumEntryIDBytes
        guard selecting.entryID.utf8.prefix(nameLimit + 1).count <= nameLimit,
              selecting.parent == parent else {
            return try refused(.selectorParentOrLength, parent: parent)
        }
        try requireCurrent()
        // Only immutable inputs cross the worker boundary. The inspector does its own index grounding.
        let input = WorkerInput(bytes: bytes, parent: parent, image: image, selection: selecting,
                                limits: detailLimits, maximumSerializedBytes: limits.maximumSerializedBytes)
        let encoded = try await Task.detached(priority: .utility) { [input] in
            let value = project(bytes: input.bytes, parent: input.parent, image: input.image,
                                selecting: input.selection, limits: input.limits)
            return try encode(value, maximum: input.maximumSerializedBytes)
        }.value
        return try finish(encoded)
    }

    /// A deferring sink must retain Prepared and call this again at its actual delivery boundary.
    static func publish(_ prepared: Prepared, to sink: (Data) throws -> Void) throws {
        try prepared.requireCurrent()
        try prepared.bridge.publish(prepared.envelope) { data in
            try prepared.requireCurrent()
            try sink(data)
        }
    }

    nonisolated private static func project(bytes: Data, parent: MachOSliceArtifactIdentity,
        image: NEWFEATURESImageKey, selecting: MachOFilesetIndex.Identity,
        limits: MachOFilesetChildInspectionLimits) -> Delivery {
        func refusal(_ reason: Refusal) -> Delivery {
            .init(image: image, parent: parent, selection: selecting, status: .refused,
                  detail: nil, refusal: reason)
        }
        do {
            let detail = try MachOParser().inspectFilesetChild(in: bytes, admittedParent: parent,
                                                              selecting: selecting, limits: limits)
            return .init(image: image, parent: parent, selection: selecting, status: .inspected,
                         detail: detail, refusal: nil)
        } catch let error as MachOFilesetChildInspectionError {
            switch error {
            case .selectorMismatch: return refusal(.selectorMismatch)
            case .limit: return refusal(.detailLimit)
            case .malformed(_, let offset): return refusal(.detailMalformed(parentOffset: offset))
            }
        } catch let error as MachOFilesetIndexError {
            switch error {
            case .unsupported(_, let offset): return refusal(.indexUnsupported(offset: offset))
            case .malformed(_, let offset): return refusal(.indexMalformed(offset: offset))
            case .limit: return refusal(.indexLimit)
            case .identityMismatch: return refusal(.indexIdentityMismatch)
            }
        } catch { return refusal(.unexpected) }
    }

    nonisolated private static func encode(_ delivery: Delivery, maximum: Int) throws -> Data {
        var remaining = maximum
        func charge(_ amount: Int) throws {
            guard amount >= 0, amount <= remaining else { throw Failure.outputLimit }
            remaining -= amount
        }
        func text(_ value: String) throws {
            // No multiplication/addition overflow, and stop as soon as the allowance is exhausted.
            for _ in value.utf8 { try charge(6) }
        }
        // All fixed keys/delimiters, enum wrappers, status/refusal, UUIDs, numeric maxima,
        // image architecture (64 ASCII bytes), raw/overall digests and THREE parent identities.
        // Every variable text occurrence below is additionally charged at JSON's six-byte maximum.
        try charge(8_192)
        if let selection = delivery.selection { try text(selection.entryID) }
        if let detail = delivery.detail {
            try text(detail.identity.entryID)
            try text(detail.semanticCoverage)
            // Fixed field keys plus maximum-width decimal numbers, booleans and enum values.
            for _ in detail.commands { try charge(512) }
            for segment in detail.segments {
                try charge(768); try text(segment.name)
            }
            for section in detail.sections {
                try charge(2_048); try text(section.sectionName); try text(section.segmentName)
            }
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(delivery)
        guard bytes.count <= maximum else { throw Failure.outputLimit }
        return bytes
    }
}
