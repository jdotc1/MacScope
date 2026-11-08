import Foundation
import NEWFEATURESCore

/// App-private inspection, not a loader, registry operation or child-image admission.
@MainActor
enum NEWFEATURESFilesetInspection {
    struct Limits: Sendable {
        var maximumImages = 256
        var maximumInputBytes = 64 * 1_024 * 1_024
        var maximumRows = 256
        var maximumSerializedBytes = 1_024 * 1_024
        var maximumElapsedSeconds = 10
        var parser = MachOFilesetIndexLimits()

        fileprivate func validatedParser() throws -> MachOFilesetIndexLimits {
            guard (1...256).contains(maximumImages), (1...64 * 1_024 * 1_024).contains(maximumInputBytes),
                  (1...256).contains(maximumRows), (1...1_024 * 1_024).contains(maximumSerializedBytes),
                  (1...10).contains(maximumElapsedSeconds) else { throw Failure.invalidLimits }
            // Reject attempts to widen the parser's contract rather than silently accepting them.
            let hard = MachOFilesetIndexLimits()
            for (value, ceiling) in [
                (parser.maximumContainerBytes, hard.maximumContainerBytes),
                (parser.maximumCommandBytes, hard.maximumCommandBytes),
                (parser.maximumCommands, hard.maximumCommands),
                (parser.maximumEntries, hard.maximumEntries),
                (parser.maximumEntryIDBytes, hard.maximumEntryIDBytes),
                (parser.maximumChildCommandBytes, hard.maximumChildCommandBytes),
                (parser.maximumSegments, hard.maximumSegments),
                (parser.maximumSections, hard.maximumSections),
                (parser.maximumMappingComparisons, hard.maximumMappingComparisons),
                (parser.maximumOutputBytes, hard.maximumOutputBytes)
            ] { guard value > 0, value <= ceiling else { throw Failure.invalidLimits } }
            var result = parser
            result.maximumContainerBytes = min(result.maximumContainerBytes, maximumInputBytes)
            // Independently bound construction before any encoder allocates its output.
            result.maximumEntries = min(result.maximumEntries, 256)
            result.maximumEntryIDBytes = min(result.maximumEntryIDBytes, 256)
            result.maximumCommands = min(result.maximumCommands, 1_024)
            result.maximumCommandBytes = min(result.maximumCommandBytes, 1_024 * 1_024)
            result.maximumChildCommandBytes = min(result.maximumChildCommandBytes, 4 * 1_024 * 1_024)
            result.maximumSegments = min(result.maximumSegments, 1_024)
            result.maximumSections = min(result.maximumSections, 8_192)
            result.maximumMappingComparisons = min(result.maximumMappingComparisons, 65_536)
            return result
        }
    }
    enum Failure: Error, Equatable {
        case invalidLimits, inputLimit, cancelled, timedOut, staleSource, outputLimit
    }
    struct Refusal: Codable, Sendable {
        let kind: String
        let reason: String
        let offset: UInt64?
    }
    struct Delivery: Codable, Sendable {
        enum Status: String, Codable, Sendable { case indexed, empty, notFound, refused }
        let image: NEWFEATURESImageKey
        let parent: MachOSliceArtifactIdentity?
        let status: Status
        let entries: [MachOFilesetIndex.Entry]
        /// Nil for refusal: an unavailable index is not a known empty index.
        let totalEntryCount: Int?
        let refusal: Refusal?
    }
    /// No Codable/memberwise authority seam; only capture can produce this value.
    struct Prepared {
        fileprivate let envelope: NEWFEATURESResultEnvelope<Data>
        fileprivate let bridge: NEWFEATURESAdmissionBridge
        fileprivate let requireCurrent: @MainActor () throws -> Void
        fileprivate init(envelope: NEWFEATURESResultEnvelope<Data>, bridge: NEWFEATURESAdmissionBridge,
                         requireCurrent: @escaping @MainActor () throws -> Void) {
            self.envelope = envelope; self.bridge = bridge; self.requireCurrent = requireCurrent
        }
    }

    /// A selector is an inert exact coordinate, never proof. No current-focus fallback.
    static func capture(slot: ImageSlot, store: WorkspaceStore, session: WorkspaceDocumentSession,
                        selecting: MachOFilesetIndex.Identity? = nil, limits: Limits = .init(),
                        now: @escaping @MainActor () -> ContinuousClock.Instant = { ContinuousClock().now },
                        isCancelled: @escaping @MainActor () -> Bool = { false }) async throws -> Prepared {
        let started = now()
        let parserLimits = try limits.validatedParser()
        let deadline = started.advanced(by: .seconds(limits.maximumElapsedSeconds))
        func requireTime() throws {
            guard !Task.isCancelled, !isCancelled() else { throw Failure.cancelled }
            guard now() < deadline else { throw Failure.timedOut }
        }
        try requireTime()
        // Bound owner lookup before the existing bridge scans the captured image spine.
        let snapshot = store.snapshot
        guard snapshot.binaries.count <= limits.maximumImages else { throw Failure.inputLimit }
        if let fingerprint = snapshot.analysis(in: slot)?.analysisInputFingerprint,
           fingerprint.facets.count > AnalysisFingerprintFacetKind.allCases.count { throw Failure.inputLimit }
        // Caller cannot supply a bridge belonging to a different store.
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
        func finish(_ delivery: Delivery) throws -> Prepared {
            try requireCurrent()
            let bytes = try encode(delivery, maximum: limits.maximumSerializedBytes)
            try requireCurrent()
            return Prepared(envelope: admission.retaining(bytes), bridge: bridge, requireCurrent: requireCurrent)
        }
        func refused(_ reason: String) throws -> Prepared {
            try finish(.init(image: image, parent: nil, status: .refused, entries: [], totalEntryCount: nil,
                refusal: .init(kind: "admission", reason: reason, offset: nil)))
        }
        let owners = snapshot.binaries.filter { $0.slot == slot }
        guard owners.count == 1, let binary = owners.first,
              let analysis = snapshot.analysis(in: slot), let fingerprint = analysis.analysisInputFingerprint
        else { return try refused("missing or ambiguous selected image") }
        guard binary.artifactIntegrityState == .verified, let parent = binary.artifactIdentity else {
            return try refused("verified artifact unavailable")
        }
        guard !analysis.imageBytes.isEmpty, analysis.imageBytes.count <= parserLimits.maximumContainerBytes else {
            return try refused("retained input bytes unavailable or limited")
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
            return try refused("selected content or owner mismatch")
        }
        if let fact = binary.machOSelectedSliceFact {
            guard fact.cpuType == parent.rawCPUType, fact.cpuSubtype == parent.rawCPUSubtype,
                  fact.universalSliceIndex == binary.selectedSliceIndex else {
                return try refused("selected slice CPU mismatch")
            }
        }
        // Thin selected bytes retain their own header. Comparing it requires no content digest.
        // Retain the whole selected parent, never a hex window or inferred child slice.
        let bytes = analysis.imageBytes
        guard bytes.count >= 12 else { return try refused("selected header unavailable") }
        func word(_ offset: Int) -> UInt32 {
            (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[bytes.startIndex + offset + $1]) << (8 * $1) }
        }
        if word(0) == MachOConstants.machMagic64 {
            guard Int32(bitPattern: word(4)) == parent.rawCPUType,
                  Int32(bitPattern: word(8)) == parent.rawCPUSubtype else {
                return try refused("selected header CPU mismatch")
            }
        } // Other container encodings retain the parser's explicit unsupported distinction.
        if let selecting {
            guard selecting.parent == parent, selecting.entryID.utf8.count <= parserLimits.maximumEntryIDBytes else {
                return try refused("selector parent or length mismatch")
            }
        }
        try requireCurrent()
        // Captures only immutable values, not a store/session, parser result or admission Boolean.
        let delivery = await Task.detached(priority: .utility) {
            project(bytes: bytes, parent: parent, image: image, selecting: selecting,
                    parserLimits: parserLimits, maximumRows: limits.maximumRows)
        }.value
        // Synchronous parser is bounded but not interruptible. Late completion never publishes.
        try requireCurrent()
        return try finish(delivery)
    }

    /// Call at the actual synchronous delivery/enqueue boundary. Deferral must call publish again.
    static func publish(_ prepared: Prepared, to sink: (Data) throws -> Void) throws {
        try prepared.requireCurrent()
        try prepared.bridge.publish(prepared.envelope) { data in
            try prepared.requireCurrent()
            try sink(data)
        }
    }

    nonisolated private static func project(bytes: Data, parent: MachOSliceArtifactIdentity,
        image: NEWFEATURESImageKey, selecting: MachOFilesetIndex.Identity?,
        parserLimits: MachOFilesetIndexLimits, maximumRows: Int) -> Delivery {
        func refusal(_ kind: String, _ reason: String, _ offset: UInt64? = nil) -> Delivery {
            .init(image: image, parent: parent, status: .refused, entries: [], totalEntryCount: nil,
                  refusal: .init(kind: kind, reason: reason, offset: offset))
        }
        do {
            let index = try MachOFilesetIndexParser().index(bytes, admittedParent: parent, limits: parserLimits)
            let rows = selecting.map { wanted in index.entries.filter { $0.identity == wanted } } ?? index.entries
            guard rows.count <= maximumRows else { return refusal("limit", "inspection rows") }
            return .init(image: image, parent: parent,
                status: rows.isEmpty ? (selecting == nil ? .empty : .notFound) : .indexed,
                entries: rows, totalEntryCount: index.entries.count, refusal: nil)
        } catch let error as MachOFilesetIndexError {
            switch error {
            case .unsupported(let reason, let offset): return refusal("unsupported", reason, offset)
            case .malformed(let reason, let offset): return refusal("malformed", reason, offset)
            case .limit(let reason): return refusal("limit", reason)
            case .identityMismatch: return refusal("identityMismatch", "parser identity mismatch")
            }
        } catch {
            return refusal("malformed", "unreadable parser input")
        }
    }

    private static func encode(_ delivery: Delivery, maximum: Int) throws -> Data {
        // Conservative JSON upper bound BEFORE encoding: fixed keys, UUIDs, decimal numbers,
        // parent/image identities and delimiters; every UTF-8 byte may expand to six bytes.
        // Structural construction already has independent parser caps. No unbounded encoder probe.
        var remaining = maximum
        func charge(_ amount: Int) throws {
            guard amount <= remaining else { throw Failure.outputLimit }; remaining -= amount
        }
        try charge(4_096)
        for row in delivery.entries {
            try charge(2_048 + row.identity.entryID.utf8.count * 6)
            for segment in row.segments { try charge(512 + segment.name.utf8.count * 6) }
        }
        if let refusal = delivery.refusal {
            try charge((refusal.kind.utf8.count + refusal.reason.utf8.count) * 6)
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(delivery)
        guard data.count <= maximum else { throw Failure.outputLimit }
        return data
    }
}
