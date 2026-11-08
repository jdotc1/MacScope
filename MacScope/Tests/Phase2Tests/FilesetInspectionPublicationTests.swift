import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

/// Synthetic real-store/session definitions. Digests are retained fixture literals.
@MainActor
final class FilesetInspectionPublicationTests: XCTestCase {
    private typealias Adapter = NEWFEATURESFilesetInspection
    private struct Harness {
        let store: WorkspaceStore
        let session: WorkspaceDocumentSession
        // The real session deliberately retains reservation authority weakly.
        let reservations: FilesetInspectionReservations
    }
    private func put32(_ data: inout Data, _ at: Int, _ value: UInt32) {
        for i in 0..<4 { data[at + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    private func put64(_ data: inout Data, _ at: Int, _ value: UInt64) {
        for i in 0..<8 { data[at + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    private func fixture(empty: Bool = false, overlapping: Bool = false) -> Data {
        var bytes = Data(repeating: 0, count: 2_048)
        put32(&bytes, 0, 0xfeedfacf); put32(&bytes, 4, 0x0100000c); put32(&bytes, 12, 12)
        put32(&bytes, 16, empty ? 0 : 2); put32(&bytes, 20, empty ? 0 : 80)
        if !empty {
            for i in 0..<2 {
                let command = 32 + i * 40, child = 512 + i * 512
                let vm: UInt64 = overlapping ? 0x1000 : UInt64(0x1000 + i * 0x1000)
                put32(&bytes, command, 0x80000035); put32(&bytes, command + 4, 40)
                put64(&bytes, command + 8, vm); put64(&bytes, command + 16, UInt64(child))
                put32(&bytes, command + 24, 32); bytes[command + 32] = UInt8(65 + i)
                put32(&bytes, child, 0xfeedfacf); put32(&bytes, child + 4, 0x0100000c)
                put32(&bytes, child + 12, 6); put32(&bytes, child + 16, 1); put32(&bytes, child + 20, 72)
                let segment = child + 32
                put32(&bytes, segment, 0x19); put32(&bytes, segment + 4, 72)
                for (j, byte) in "__TEXT".utf8.enumerated() { bytes[segment + 8 + j] = byte }
                put64(&bytes, segment + 24, vm); put64(&bytes, segment + 32, 128)
                put64(&bytes, segment + 40, UInt64(child)); put64(&bytes, segment + 48, 128)
            }
        }
        return bytes
    }
    private func harness(bytes: Data? = nil, digest: String = String(repeating: "b", count: 64),
                         mutation: (inout BinaryImage, inout ImageAnalysis) throws -> Void = { _, _ in }) throws -> Harness {
        let bytes = bytes ?? fixture(), id = UUID()
        let artifact = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c, rawCPUSubtype: 0,
            selectedSliceSHA256: digest, selectedSliceByteCount: UInt64(bytes.count))
        var binary = BinaryImage(id: id, name: "retained-fileset", path: "/not-opened/fileset", kind: "Mach-O",
            architecture: "arm64", selectedSliceIndex: nil,
            machOSelectedSliceFact: try .init(containerKind: .thin, sliceCount: 1,
                selectedSliceIndex: 0, cpuType: 0x0100000c, cpuSubtype: 0),
            artifactIdentity: artifact,
            preferredSegmentLayout: try .init(records: [], selectedSliceByteCount: UInt64(bytes.count)),
            artifactIntegrityState: .verified, slot: .primary)
        var analysis = ImageAnalysis()
        analysis.imageBytes = bytes
        analysis.analysisInputFingerprint = try .init(imageSlot: .primary, binaryID: id,
            binaryName: binary.name, binaryPath: binary.path, selectedSliceIndex: nil,
            artifactIdentity: artifact, imageByteCount: UInt64(bytes.count), imageBytesSHA256: digest,
            facets: [], overallSHA256: String(repeating: "a", count: 64))
        try mutation(&binary, &analysis)
        let store = WorkspaceStore(workspaceName: "fileset", snapshot: .init(binaries: [binary],
            analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let reservations = FilesetInspectionReservations()
        let session = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
            source: store, io: WorkspaceDocumentIO(), reservations: reservations)
        return .init(store: store, session: session, reservations: reservations)
    }
    private func capture(_ h: Harness, selecting: MachOFilesetIndex.Identity? = nil,
                         limits: Adapter.Limits = .init()) async throws -> Adapter.Prepared {
        try await Adapter.capture(slot: .primary, store: h.store, session: h.session,
            selecting: selecting, limits: limits)
    }
    private func delivery(_ prepared: Adapter.Prepared) throws -> Adapter.Delivery {
        var result: Adapter.Delivery?
        try Adapter.publish(prepared) { result = try JSONDecoder().decode(Adapter.Delivery.self, from: $0) }
        return try XCTUnwrap(result)
    }
    private func suppress(_ prepared: Adapter.Prepared, file: StaticString = #filePath, line: UInt = #line) {
        var writes = 0
        XCTAssertThrowsError(try Adapter.publish(prepared) { _ in writes += 1 }, file: file, line: line)
        XCTAssertEqual(writes, 0, file: file, line: line)
    }
    func testActualCaptureRetainsRawHashNotOverallAndAbsoluteCoordinates() async throws {
        let h = try harness(); defer { h.session.close() }
        let value = try await capture(h); let result = try delivery(value)
        XCTAssertEqual(result.status, .indexed)
        XCTAssertEqual(result.image.contentSHA256, String(repeating: "b", count: 64))
        XCTAssertEqual(result.image.analysisInputFingerprintSHA256, String(repeating: "a", count: 64))
        XCTAssertEqual(result.entries.map(\.identity.fileOffset), [512, 1_024])
        XCTAssertEqual(result.entries.map(\.segments.first?.fileOffset), [512, 1_024])
        XCTAssertTrue(result.entries.allSatisfy { $0.identity.parent == result.parent })
    }
    func testSameAddressesAndNamesUnderDifferentRawParentsRemainDistinct() async throws {
        let a = try harness(), b = try harness(digest: String(repeating: "c", count: 64))
        defer { a.session.close(); b.session.close() }
        let first = try await capture(a), second = try await capture(b)
        XCTAssertNotEqual(try delivery(first).entries[0].identity, try delivery(second).entries[0].identity)
    }
    func testMissingUUIDAndSharedVirtualMappingsRemainHonest() async throws {
        let h = try harness(bytes: fixture(overlapping: true)); defer { h.session.close() }
        let value = try await capture(h); let result = try delivery(value)
        XCTAssertTrue(result.entries.allSatisfy { $0.childUUID == nil && $0.sharesOrOverlapsAnotherEntry })
        XCTAssertNotEqual(result.entries[0].identity, result.entries[1].identity)
    }
    func testExactEntrySelectionCannotBorrowAnotherParentOrNameAlone() async throws {
        let h = try harness(), other = try harness(digest: String(repeating: "d", count: 64))
        defer { h.session.close(); other.session.close() }
        let current = try await capture(h), foreign = try await capture(other)
        let own = try delivery(current).entries[0].identity
        let selected = try await capture(h, selecting: own)
        XCTAssertEqual(try delivery(selected).entries.count, 1)
        let wrong = try await capture(h, selecting: delivery(foreign).entries[0].identity)
        XCTAssertEqual(try delivery(wrong).refusal?.reason, "selector parent or length mismatch")
        let absent = MachOFilesetIndex.Identity(parent: own.parent, commandOffset: own.commandOffset + 1,
            fileOffset: own.fileOffset, virtualAddress: own.virtualAddress, entryID: own.entryID)
        let missing = try await capture(h, selecting: absent)
        XCTAssertEqual(try delivery(missing).status, .notFound)
    }
    func testRawFingerprintCountAndArtifactMismatchRefuseBeforeMalformedBytesAreParsed() async throws {
        for mode in 0..<4 {
            var bad = fixture(); put32(&bad, 0, 0)
            let h = try harness(bytes: bad) { binary, analysis in
                switch mode {
                case 0: analysis.analysisInputFingerprint?.imageBytesSHA256 = String(repeating: "c", count: 64)
                case 1: analysis.analysisInputFingerprint?.imageByteCount = 1
                case 2: analysis.analysisInputFingerprint?.artifactIdentity = nil
                default: binary.artifactIntegrityState = .unavailable
                }
            }
            defer { h.session.close() }
            let value = try await capture(h)
            XCTAssertEqual(try delivery(value).refusal?.kind, "admission")
            XCTAssertNil(try delivery(value).totalEntryCount)
        }
    }
    func testRawHeaderCPUAndRetainedSliceCPUMismatchRefuseBeforeParser() async throws {
        var bad = fixture(); put32(&bad, 4, 0x01000007)
        let a = try harness(bytes: bad)
        let b = try harness { binary, _ in
            binary.machOSelectedSliceFact = try .init(containerKind: .thin, sliceCount: 1,
                selectedSliceIndex: 0, cpuType: 0x0100000c, cpuSubtype: 2)
        }
        defer { a.session.close(); b.session.close() }
        let first = try await capture(a), second = try await capture(b)
        XCTAssertEqual(try delivery(first).refusal?.reason, "selected header CPU mismatch")
        XCTAssertEqual(try delivery(second).refusal?.reason, "selected slice CPU mismatch")
    }
    func testMissingFingerprintIsNotEmptyAndWrongSessionCannotLendItsBridge() async throws {
        let missing = try harness { _, analysis in analysis.analysisInputFingerprint = nil }
        let a = try harness(), b = try harness()
        defer { missing.session.close(); a.session.close(); b.session.close() }
        do { _ = try await capture(missing); XCTFail("missing identity admitted") } catch {}
        do {
            _ = try await Adapter.capture(slot: .primary, store: a.store, session: b.session)
            XCTFail("another store's session admitted")
        } catch {}
    }
    func testEmptyUnsupportedAndMalformedAreNotConflated() async throws {
        var unsupported = fixture(); put32(&unsupported, 0, 0x706d6f63)
        var malformed = fixture(); put32(&malformed, 20, 72)
        for (bytes, status, kind) in [(fixture(empty: true), Adapter.Delivery.Status.empty, nil as String?),
                                     (unsupported, .refused, "unsupported"), (malformed, .refused, "malformed")] {
            let h = try harness(bytes: bytes); defer { h.session.close() }
            let value = try await capture(h); let result = try delivery(value)
            XCTAssertEqual(result.status, status); XCTAssertEqual(result.refusal?.kind, kind)
            XCTAssertEqual(result.totalEntryCount, status == .empty ? 0 : nil)
        }
    }
    func testCloseAndReopenCannotPublishPositiveEmptyOrError() async throws {
        var errorBytes = fixture(); put32(&errorBytes, 20, 72)
        for bytes in [fixture(), fixture(empty: true), errorBytes] {
            let h = try harness(bytes: bytes); let value = try await capture(h)
            h.session.close()
            let replacement = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
                source: h.store, io: WorkspaceDocumentIO(), reservations: h.reservations)
            defer { replacement.close() }
            suppress(value)
        }
    }
    func testAnalysisRevisionAndSlotReuseSuppressAllResultKinds() async throws {
        var errorBytes = fixture(); put32(&errorBytes, 20, 72)
        for bytes in [fixture(), fixture(empty: true), errorBytes] {
            for reuse in [false, true] {
                let h = try harness(bytes: bytes); defer { h.session.close() }
                let value = try await capture(h)
                if reuse {
                    let next = try harness(); defer { next.session.close() }
                    h.store.snapshot = next.store.snapshot
                } else {
                    var snapshot = h.store.snapshot
                    snapshot.analysisBySlot[.primary]?.imageBytes[31] = 1
                    h.store.snapshot = snapshot
                }
                suppress(value)
            }
        }
    }
    func testCancellationAtActualPublicationSuppressesPositiveEmptyAndError() async throws {
        var errorBytes = fixture(); put32(&errorBytes, 20, 72)
        for bytes in [fixture(), fixture(empty: true), errorBytes] {
            let h = try harness(bytes: bytes); defer { h.session.close() }
            var cancelled = false
            let value = try await Adapter.capture(slot: .primary, store: h.store, session: h.session,
                isCancelled: { cancelled })
            cancelled = true; suppress(value)
        }
    }
    func testDeadlineAtActualPublicationSuppressesPositiveEmptyAndError() async throws {
        var errorBytes = fixture(); put32(&errorBytes, 20, 72)
        for bytes in [fixture(), fixture(empty: true), errorBytes] {
            let h = try harness(bytes: bytes); defer { h.session.close() }
            let start = ContinuousClock().now; var instant = start
            let value = try await Adapter.capture(slot: .primary, store: h.store, session: h.session,
                now: { instant })
            instant = start.advanced(by: .seconds(11)); suppress(value)
        }
    }
    func testCancellationBeforeCaptureDoesNotReturnAuthority() async throws {
        let h = try harness(); defer { h.session.close() }
        do {
            _ = try await Adapter.capture(slot: .primary, store: h.store, session: h.session, isCancelled: { true })
            XCTFail("cancelled capture returned authority")
        } catch { XCTAssertEqual(error as? Adapter.Failure, .cancelled) }
    }
    func testDeadlineAfterSynchronousWorkSuppressesResultWithoutInterruptionClaim() async throws {
        let h = try harness(); defer { h.session.close() }
        let start = ContinuousClock().now; var observations = 0
        do {
            _ = try await Adapter.capture(slot: .primary, store: h.store, session: h.session, now: {
                observations += 1
                return observations < 4 ? start : start.advanced(by: .seconds(11))
            })
            XCTFail("late result returned authority")
        } catch { XCTAssertEqual(error as? Adapter.Failure, .timedOut) }
    }
    func testRowCapRefusalDoesNotBecomePartialEmptyOrNotFound() async throws {
        let h = try harness(); defer { h.session.close() }
        var limits = Adapter.Limits(); limits.maximumRows = 1
        let value = try await capture(h, limits: limits); let result = try delivery(value)
        XCTAssertEqual(result.status, .refused); XCTAssertEqual(result.refusal?.kind, "limit")
        XCTAssertNil(result.totalEntryCount); XCTAssertTrue(result.entries.isEmpty)
    }
    func testCompleteEncodedWrapperIsChargedBeforeAllocation() async throws {
        let h = try harness(bytes: fixture(empty: true)); defer { h.session.close() }
        var limits = Adapter.Limits(); limits.maximumSerializedBytes = 1
        do { _ = try await capture(h, limits: limits); XCTFail("wrapper omitted from cap") }
        catch { XCTAssertEqual(error as? Adapter.Failure, .outputLimit) }
        limits.maximumSerializedBytes = 8_192
        let value = try await capture(h, limits: limits)
        try Adapter.publish(value) { XCTAssertLessThanOrEqual($0.count, 8_192) }
    }
    func testStricterParserCapsAndInputCapsNeverWidenOrFallback() async throws {
        let h = try harness(); defer { h.session.close() }
        var limits = Adapter.Limits(); limits.parser.maximumEntries = 1
        let one = try await capture(h, limits: limits)
        XCTAssertEqual(try delivery(one).refusal?.kind, "limit")
        limits = .init(); limits.maximumInputBytes = 100
        let small = try await capture(h, limits: limits)
        XCTAssertEqual(try delivery(small).refusal?.kind, "admission")
        limits = .init(); limits.parser.maximumEntries = 1_025
        do { _ = try await capture(h, limits: limits); XCTFail("widened limit") }
        catch { XCTAssertEqual(error as? Adapter.Failure, .invalidLimits) }
    }
    func testDecodedIndexCannotBeSubmittedAsPreparedAuthority() async throws {
        let h = try harness(); defer { h.session.close() }
        let value = try await capture(h); let observed = try delivery(value)
        let inert = MachOFilesetIndex(parent: try XCTUnwrap(observed.parent), entries: [])
        let decoded = try JSONDecoder().decode(MachOFilesetIndex.self, from: JSONEncoder().encode(inert))
        XCTAssertTrue(decoded.entries.isEmpty)
        // No capture(index:) or Prepared(index:) API exists. Only a fresh real capture is executable.
        let again = try await capture(h)
        XCTAssertEqual(try delivery(again).entries.count, 2)
    }
}

@MainActor
private final class FilesetInspectionReservations: WorkspaceDocumentLocationReserving {
    private struct Reservation {
        let sessionID: WorkspaceDocumentSessionID
        let windowID: WorkspaceWindowID
        let physicalIdentity: WorkspaceFileObjectIdentity?
    }

    private struct Publication {
        let sessionID: WorkspaceDocumentSessionID
        let windowID: WorkspaceWindowID
        let retainingPublishedOwnership: Bool
    }

    private var reservations: [URL: Reservation] = [:]
    private var reservationsByPhysicalIdentity: [WorkspaceFileObjectIdentity: Reservation] = [:]
    private var forcedOwners: [URL: WorkspaceWindowID] = [:]
    private(set) var releasedLocations: [WorkspaceDocumentLocation] = []
    private(set) var releaseAllCount = 0
    private var activePublications:
        [WorkspaceDocumentPublicationReservation: Publication] = [:]
    private var nextPublicationCompletion:
        WorkspaceDocumentPublicationCompletionResult?
    private(set) var completedPublicationCount = 0

    var activePublicationCount: Int { activePublications.count }

    func forceNextPublicationCompletion(
        _ result: WorkspaceDocumentPublicationCompletionResult
    ) {
        nextPublicationCompletion = result
    }

    func forceOwner(_ owner: WorkspaceWindowID, for location: WorkspaceDocumentLocation) {
        forcedOwners[location.canonicalURL] = owner
    }

    func owner(of location: WorkspaceDocumentLocation) -> WorkspaceWindowID? {
        forcedOwners[location.canonicalURL]
            ?? reservations[location.canonicalURL]?.windowID
            ?? location.fileObjectIdentity.flatMap {
                reservationsByPhysicalIdentity[$0]?.windowID
            }
    }

    func reserve(
        _ location: WorkspaceDocumentLocation,
        for sessionID: WorkspaceDocumentSessionID,
        windowID: WorkspaceWindowID
    ) -> WorkspaceDocumentLocationReservationResult {
        if let forced = forcedOwners[location.canonicalURL] {
            return .alreadyOwned(forced)
        }
        if let existing = reservations[location.canonicalURL] {
            if existing.sessionID != sessionID {
                return .alreadyOwned(existing.windowID)
            }
        }
        if let identity = location.fileObjectIdentity,
           let existing = reservationsByPhysicalIdentity[identity],
           existing.sessionID != sessionID {
            return .alreadyOwned(existing.windowID)
        }
        let priorIdentity = reservations[location.canonicalURL]?.physicalIdentity
        let reservation = Reservation(
            sessionID: sessionID,
            windowID: windowID,
            physicalIdentity: location.fileObjectIdentity
        )
        reservations[location.canonicalURL] = reservation
        if let identity = location.fileObjectIdentity {
            reservationsByPhysicalIdentity[identity] = reservation
        }
        if priorIdentity != location.fileObjectIdentity,
           let priorIdentity,
           !reservations.values.contains(where: { owner in
               owner.physicalIdentity == priorIdentity
           }) {
            reservationsByPhysicalIdentity[priorIdentity] = nil
        }
        return .reserved
    }

    func release(
        _ location: WorkspaceDocumentLocation,
        for sessionID: WorkspaceDocumentSessionID
    ) {
        releasedLocations.append(location)
        guard let reservation = reservations[location.canonicalURL],
              reservation.sessionID == sessionID else { return }
        reservations[location.canonicalURL] = nil
        if let identity = location.fileObjectIdentity,
           reservationsByPhysicalIdentity[identity]?.sessionID == reservation.sessionID,
           reservationsByPhysicalIdentity[identity]?.windowID == reservation.windowID {
            reservationsByPhysicalIdentity[identity] = nil
        }
    }

    func releaseAll(for sessionID: WorkspaceDocumentSessionID) {
        releaseAllCount += 1
        reservations = reservations.filter { $0.value.sessionID != sessionID }
        reservationsByPhysicalIdentity = reservationsByPhysicalIdentity.filter {
            $0.value.sessionID != sessionID
        }
    }

    func beginPhysicalPublication(
        _ staged: WorkspaceDocumentStagedPackage,
        to destination: WorkspaceDocumentLocation,
        retainingPublishedOwnership: Bool,
        for sessionID: WorkspaceDocumentSessionID,
        windowID: WorkspaceWindowID
    ) -> WorkspaceDocumentPublicationReservationResult {
        if let owner = owner(of: destination), owner != windowID {
            return .alreadyOwned(owner)
        }
        let publication = WorkspaceDocumentPublicationReservation()
        activePublications[publication] = Publication(
            sessionID: sessionID,
            windowID: windowID,
            retainingPublishedOwnership: retainingPublishedOwnership
        )
        return .reserved(publication)
    }

    func completePhysicalPublication(
        _ publication: WorkspaceDocumentPublicationReservation,
        at publishedLocation: WorkspaceDocumentLocation
    ) -> WorkspaceDocumentPublicationCompletionResult {
        guard let pending = activePublications.removeValue(forKey: publication) else {
            return .invalid
        }
        if let forced = nextPublicationCompletion {
            nextPublicationCompletion = nil
            return forced
        }
        if pending.retainingPublishedOwnership {
            guard case .reserved = reserve(
                publishedLocation,
                for: pending.sessionID,
                windowID: pending.windowID
            ) else {
                return .invalid
            }
        }
        completedPublicationCount += 1
        return .completed
    }

    func cancelPhysicalPublication(
        _ publication: WorkspaceDocumentPublicationReservation
    ) {
        activePublications[publication] = nil
    }

    func isReserved(
        _ location: WorkspaceDocumentLocation,
        by sessionID: WorkspaceDocumentSessionID
    ) -> Bool {
        reservations[location.canonicalURL]?.sessionID == sessionID
    }
}

