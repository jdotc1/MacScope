import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

@MainActor
final class FilesetChildDetailPublicationTests: XCTestCase {
    private typealias Adapter = NEWFEATURESFilesetChildDetailInspection
    private struct Harness {
        let store: WorkspaceStore
        let session: WorkspaceDocumentSession
        let reservations: FilesetChildDetailReservations
    }
    private func put32(_ bytes: inout Data, _ at: Int, _ value: UInt32) {
        for shift in 0..<4 { bytes[at + shift] = UInt8(truncatingIfNeeded: value >> (shift * 8)) }
    }
    private func put64(_ bytes: inout Data, _ at: Int, _ value: UInt64) {
        for shift in 0..<8 { bytes[at + shift] = UInt8(truncatingIfNeeded: value >> (shift * 8)) }
    }
    private func name(_ bytes: inout Data, _ at: Int, _ value: String) {
        for (position, byte) in value.utf8.enumerated() { bytes[at + position] = byte }
    }
    private func header(_ bytes: inout Data, _ at: Int, _ kind: UInt32, _ count: UInt32, _ size: UInt32) {
        put32(&bytes, at, 0xfeedfacf); put32(&bytes, at + 4, 0x0100000c)
        put32(&bytes, at + 12, kind); put32(&bytes, at + 16, count); put32(&bytes, at + 20, size)
    }
    private func entry(_ bytes: inout Data, _ at: Int, _ child: UInt64, _ vm: UInt64, _ id: String) {
        put32(&bytes, at, 0x80000035); put32(&bytes, at + 4, 40)
        put64(&bytes, at + 8, vm); put64(&bytes, at + 16, child)
        put32(&bytes, at + 24, 32); name(&bytes, at + 32, id)
    }
    private func fixture(neighbor: Bool = false, uuid: Bool = true) -> Data {
        var bytes = Data(repeating: 0, count: 4_096)
        header(&bytes, 0, 12, neighbor ? 2 : 1, neighbor ? 80 : 40)
        entry(&bytes, 32, 512, 0x1000, "first")
        header(&bytes, 512, 6, uuid ? 3 : 2, uuid ? 264 : 240)
        put32(&bytes, 544, 0x19); put32(&bytes, 548, 232); name(&bytes, 552, "__DATA")
        put64(&bytes, 568, 0x1000); put64(&bytes, 576, 0x800)
        put64(&bytes, 584, 512); put64(&bytes, 592, 0x700); put32(&bytes, 608, 2)
        name(&bytes, 616, "__data"); name(&bytes, 632, "__DATA")
        put64(&bytes, 648, 0x1600); put64(&bytes, 656, 16); put32(&bytes, 664, 2_048)
        put32(&bytes, 668, 3)
        name(&bytes, 696, "__bss"); name(&bytes, 712, "__DATA")
        put64(&bytes, 728, 0x1780); put64(&bytes, 736, 32)
        put32(&bytes, 748, 4); put32(&bytes, 760, 1)
        if uuid {
            put32(&bytes, 776, 0x1b); put32(&bytes, 780, 24); bytes[784] = 0x11
        }
        let unknown = uuid ? 800 : 776
        put32(&bytes, unknown, 0x7777); put32(&bytes, unknown + 4, 8)
        bytes[2_048] = 0xa5; bytes[2_560] = 0x5a
        if neighbor {
            entry(&bytes, 72, 1_024, 0x4000, "next")
            header(&bytes, 1_024, 6, 1, 72)
            put32(&bytes, 1_056, 0x19); put32(&bytes, 1_060, 72); name(&bytes, 1_064, "__TEXT")
            put64(&bytes, 1_080, 0x4000); put64(&bytes, 1_088, 128)
            put64(&bytes, 1_096, 1_024); put64(&bytes, 1_104, 128)
        }
        return bytes
    }
    private func harness(bytes: Data? = nil, digest: String = String(repeating: "b", count: 64),
                         slot: ImageSlot = .primary, parentUUID: UUID? = nil, mutation: (inout BinaryImage, inout ImageAnalysis) throws -> Void = { _, _ in }) throws -> Harness {
        let bytes = bytes ?? fixture(), id = UUID()
        let artifact = try MachOSliceArtifactIdentity(uuid: parentUUID, rawCPUType: 0x0100000c, rawCPUSubtype: 0,
            selectedSliceSHA256: digest, selectedSliceByteCount: UInt64(bytes.count))
        var binary = BinaryImage(id: id, name: "retained-fileset", path: "/not-opened/fileset", kind: "Mach-O",
            architecture: "arm64", selectedSliceIndex: nil,
            machOSelectedSliceFact: try .init(containerKind: .thin, sliceCount: 1,
                selectedSliceIndex: 0, cpuType: 0x0100000c, cpuSubtype: 0),
            artifactIdentity: artifact,
            preferredSegmentLayout: try .init(records: [], selectedSliceByteCount: UInt64(bytes.count)),
            artifactIntegrityState: .verified, slot: slot)
        var analysis = ImageAnalysis()
        analysis.imageBytes = bytes
        analysis.analysisInputFingerprint = try .init(imageSlot: slot, binaryID: id,
            binaryName: binary.name, binaryPath: binary.path, selectedSliceIndex: nil,
            artifactIdentity: artifact, imageByteCount: UInt64(bytes.count), imageBytesSHA256: digest,
            facets: [], overallSHA256: String(repeating: "a", count: 64))
        try mutation(&binary, &analysis)
        let store = WorkspaceStore(workspaceName: "fileset", snapshot: .init(binaries: [binary],
            analysisBySlot: [slot: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let reservations = FilesetChildDetailReservations()
        let session = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
            source: store, io: WorkspaceDocumentIO(), reservations: reservations)
        return .init(store: store, session: session, reservations: reservations)
    }

    private func selector(_ h: Harness, slot: ImageSlot = .primary,
                          commandOffset: UInt64 = 32, fileOffset: UInt64 = 512,
                          virtualAddress: UInt64 = 0x1000, entryID: String = "first") throws -> MachOFilesetIndex.Identity {
        let binary = try XCTUnwrap(h.store.snapshot.binaries.first { $0.slot == slot })
        return .init(parent: try XCTUnwrap(binary.artifactIdentity), commandOffset: commandOffset,
                     fileOffset: fileOffset, virtualAddress: virtualAddress, entryID: entryID)
    }
    private func capture(_ h: Harness, selecting: MachOFilesetIndex.Identity? = nil,
                         slot: ImageSlot = .primary, limits: Adapter.Limits = .init()) async throws -> Adapter.Prepared {
        let selected = try selecting ?? selector(h, slot: slot)
        return try await Adapter.capture(slot: slot, store: h.store, session: h.session,
                                         selecting: selected, limits: limits)
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
    private func requireRefusal(_ value: Adapter.Delivery, _ reason: Adapter.Refusal,
                                file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(value.status, .refused, file: file, line: line)
        XCTAssertEqual(value.refusal, reason, file: file, line: line)
        XCTAssertNil(value.detail, file: file, line: line)
    }
    private enum Outcome: CaseIterable, Equatable {
        case success, admission, selector, detailLimit, detailMalformed
        case indexUnsupported, indexMalformed, indexLimit, indexIdentityMismatch
    }
    private struct OutcomeInput {
        let harness: Harness
        let selection: MachOFilesetIndex.Identity
        let limits: Adapter.Limits
        let refusal: Adapter.Refusal?
    }
    private func outcome(_ kind: Outcome) throws -> OutcomeInput {
        var bytes = fixture(neighbor: true), limits = Adapter.Limits()
        var refusal: Adapter.Refusal?, parentUUID: UUID?
        switch kind {
        case .success: break
        case .admission: break
        case .selector: refusal = .selectorMismatch
        case .detailLimit: limits.detail.maximumCommands = 2; refusal = .detailLimit
        case .detailMalformed: bytes[632] = 65; refusal = .detailMalformed(parentOffset: 616)
        case .indexUnsupported: put32(&bytes, 0, 0x706d6f63); refusal = .indexUnsupported(offset: 0)
        case .indexMalformed: put32(&bytes, 20, 32); refusal = .indexMalformed(offset: 32)
        case .indexLimit: limits.detail.indexLimits.maximumEntries = 1; refusal = .indexLimit
        case .indexIdentityMismatch:
            put32(&bytes, 16, 3); put32(&bytes, 20, 104)
            put32(&bytes, 112, 0x1b); put32(&bytes, 116, 24); bytes[120] = 1
            parentUUID = UUID(uuidString: "02000000-0000-0000-0000-000000000000")
            refusal = .indexIdentityMismatch
        }
        let h = try harness(bytes: bytes, parentUUID: parentUUID) { binary, _ in
            if kind == .admission { binary.artifactIntegrityState = .unavailable }
        }
        if kind == .admission { refusal = .admission(.artifactUnavailable) }
        let selected = try selector(h, entryID: kind == .selector ? "missing" : "first")
        return .init(harness: h, selection: selected, limits: limits, refusal: refusal)
    }
    private func requireOutcome(_ value: Adapter.Delivery, input: OutcomeInput) {
        if let refusal = input.refusal { requireRefusal(value, refusal) }
        else { XCTAssertEqual(value.status, .inspected); XCTAssertNotNil(value.detail); XCTAssertNil(value.refusal) }
    }
    func testCaptureDeliversExactOwnerSelectorAndUsefulDetail() async throws {
        let h = try harness(); defer { h.session.close() }
        let selected = try selector(h)
        let prepared = try await capture(h, selecting: selected)
        let value = try delivery(prepared), detail = try XCTUnwrap(value.detail)
        XCTAssertEqual(value.status, .inspected); XCTAssertNil(value.refusal)
        XCTAssertEqual(value.image.binaryID, h.store.snapshot.binaries[0].id)
        XCTAssertEqual(value.image.slot, ImageSlot.primary.rawValue)
        XCTAssertEqual(value.parent, selected.parent); XCTAssertEqual(value.selection, selected)
        XCTAssertEqual(detail.identity, selected)
        XCTAssertEqual(detail.commands.map(\.coverage), [.segmentAndSections, .uuid, .envelopeOnly])
        XCTAssertEqual(detail.sections.map(\.sectionName), ["__data", "__bss"])
        XCTAssertEqual(detail.sections[0].recordParentFileOffset, 616)
        XCTAssertTrue(detail.sections[1].isZeroFill); XCTAssertNil(detail.sections[1].parentFileOffset)
    }
    func testWholeParentNonzeroOriginAndNeighborGeometrySurviveCapture() async throws {
        let original = fixture(neighbor: true)
        var padded = Data(repeating: 0, count: 16); padded.append(original)
        let retained = padded.dropFirst(16)
        XCTAssertNotEqual(retained.startIndex, 0)
        let h = try harness(bytes: retained); defer { h.session.close() }
        let prepared = try await capture(h), detail = try XCTUnwrap(delivery(prepared).detail)
        XCTAssertEqual(detail.sections[0].parentFileOffset, 2_048)
        XCTAssertEqual(detail.commands[0].parentFileOffset, 544)
        XCTAssertEqual(detail.commands[0].offsetFromChildHeader, 32)
        XCTAssertEqual(detail.segments[0].fileOffset, 512)
        XCTAssertEqual(detail.segments[0].fileSize, 0x700)
        XCTAssertTrue(detail.sharesOrOverlapsAnotherEntry)
        let at = Int(try XCTUnwrap(detail.sections[0].parentFileOffset))
        XCTAssertEqual(retained[retained.startIndex + at], 0xa5)
        XCTAssertEqual(retained[retained.startIndex + 512 + at], 0x5a)
    }
    func testSelectedZeroSectionChildWithoutUUIDIsSuccessful() async throws {
        let h = try harness(bytes: fixture(neighbor: true)); defer { h.session.close() }
        let selected = try selector(h, commandOffset: 72, fileOffset: 1_024, virtualAddress: 0x4000, entryID: "next")
        let prepared = try await capture(h, selecting: selected), value = try delivery(prepared)
        XCTAssertEqual(value.status, .inspected); XCTAssertNil(value.refusal)
        let detail = try XCTUnwrap(value.detail)
        XCTAssertEqual(detail.identity, selected); XCTAssertTrue(detail.sections.isEmpty)
        XCTAssertNil(detail.childUUID); XCTAssertEqual(detail.commands.count, 1)
    }
    func testRawDigestRemainsSeparateFromOverallFingerprint() async throws {
        let h = try harness(); defer { h.session.close() }
        let prepared = try await capture(h), value = try delivery(prepared)
        let detail = try XCTUnwrap(value.detail), parent = try XCTUnwrap(value.parent)
        XCTAssertEqual(value.image.contentSHA256, String(repeating: "b", count: 64))
        XCTAssertEqual(value.image.analysisInputFingerprintSHA256, String(repeating: "a", count: 64))
        XCTAssertEqual(parent.selectedSliceSHA256, value.image.contentSHA256)
        XCTAssertEqual(detail.identity.parent.selectedSliceSHA256, value.image.contentSHA256)
        XCTAssertNotEqual(detail.identity.parent.selectedSliceSHA256, value.image.analysisInputFingerprintSHA256)
    }
    func testForeignParentAndAlteredCoordinatesCannotBorrowChild() async throws {
        let h = try harness(), foreign = try harness(digest: String(repeating: "c", count: 64))
        defer { h.session.close(); foreign.session.close() }
        let foreignPrepared = try await capture(h, selecting: selector(foreign))
        let foreignValue = try delivery(foreignPrepared)
        requireRefusal(foreignValue, .admission(.selectorParentOrLength))
        XCTAssertNil(foreignValue.selection)
        for selected in [try selector(h, commandOffset: 40), try selector(h, fileOffset: 520),
                         try selector(h, virtualAddress: 0x1008)] {
            let prepared = try await capture(h, selecting: selected)
            requireRefusal(try delivery(prepared), .selectorMismatch)
        }
        let oversized = try selector(h, entryID: String(repeating: "x", count: 4_096))
        let prepared = try await capture(h, selecting: oversized), value = try delivery(prepared)
        requireRefusal(value, .admission(.selectorParentOrLength)); XCTAssertNil(value.selection)
    }
    func testMissingExactSelectorIsHonestMismatchWithoutFabricatedDetail() async throws {
        let h = try harness(); defer { h.session.close() }
        let selected = try selector(h, entryID: "missing")
        let prepared = try await capture(h, selecting: selected), value = try delivery(prepared)
        requireRefusal(value, .selectorMismatch); XCTAssertEqual(value.selection, selected)
    }
    func testAdmissionMismatchesPrecedeMalformedDetailClassification() async throws {
        let missing = try harness { _, analysis in analysis.analysisInputFingerprint = nil }
        defer { missing.session.close() }
        do { _ = try await capture(missing); XCTFail("missing fingerprint admitted") }
        catch { XCTAssertEqual(error as? NEWFEATURESAdmissionFailure, .analysisRequired) }
        let reasons: [Adapter.AdmissionReason] = [.ownerMismatch, .ownerMismatch, .ownerMismatch,
                                                 .artifactUnavailable, .sliceCPU, .headerCPU]
        for mode in reasons.indices {
            var bytes = fixture(); bytes[616] = 0xff
            if mode == 5 { put32(&bytes, 4, 0x01000007) }
            let h = try harness(bytes: bytes) { binary, analysis in
                switch mode {
                case 0: analysis.analysisInputFingerprint?.imageBytesSHA256 = String(repeating: "d", count: 64)
                case 1: analysis.analysisInputFingerprint?.imageByteCount = 1
                case 2: analysis.analysisInputFingerprint?.artifactIdentity = nil
                case 3: binary.artifactIntegrityState = .unavailable
                case 4: binary.machOSelectedSliceFact = try .init(containerKind: .thin, sliceCount: 1,
                    selectedSliceIndex: 0, cpuType: 0x0100000c, cpuSubtype: 2)
                default: break
                }
            }
            defer { h.session.close() }
            let prepared = try await capture(h), value = try delivery(prepared)
            requireRefusal(value, .admission(reasons[mode])); XCTAssertNil(value.selection)
        }
    }
    func testExplicitSecondarySlotUsesItsOwnParentNotPrimary() async throws {
        let secondary = ImageSlot(rawValue: 1)
        let primary = try harness(), h = try harness(digest: String(repeating: "c", count: 64), slot: secondary)
        defer { primary.session.close(); h.session.close() }
        h.store.snapshot = .init(binaries: primary.store.snapshot.binaries + h.store.snapshot.binaries,
            analysisBySlot: [.primary: try XCTUnwrap(primary.store.snapshot.analysis(in: .primary)),
                            secondary: try XCTUnwrap(h.store.snapshot.analysis(in: secondary))])
        let own = try selector(h, slot: secondary), wrong = try selector(primary)
        let prepared = try await capture(h, selecting: own, slot: secondary), value = try delivery(prepared)
        XCTAssertEqual(value.image.slot, 1); XCTAssertEqual(value.parent, own.parent)
        XCTAssertEqual(value.detail?.identity, own); XCTAssertNotEqual(value.parent, wrong.parent)
        let refused = try await capture(h, selecting: wrong, slot: secondary)
        requireRefusal(try delivery(refused), .admission(.selectorParentOrLength))
    }
    func testInvalidWidenedAndStricterBudgetsNeverYieldPartialDetail() async throws {
        let h = try harness(bytes: fixture(neighbor: true)); defer { h.session.close() }
        var invalid = Adapter.Limits(); invalid.maximumImages = 0
        var widened = Adapter.Limits(); widened.detail.maximumSections = 8_193
        var widenedIndex = Adapter.Limits(); widenedIndex.detail.indexLimits.maximumEntries = 1_025
        for limits in [invalid, widened, widenedIndex] {
            do { _ = try await capture(h, limits: limits); XCTFail("invalid limits admitted") }
            catch { XCTAssertEqual(error as? Adapter.Failure, .invalidLimits) }
        }
        var input = Adapter.Limits(); input.maximumInputBytes = 100
        let small = try await capture(h, limits: input)
        requireRefusal(try delivery(small), .admission(.inputUnavailable))
        var innerInput = Adapter.Limits(); innerInput.detail.maximumInputBytes = 100
        let innerSmall = try await capture(h, limits: innerInput)
        requireRefusal(try delivery(innerSmall), .admission(.inputUnavailable))
        var commands = Adapter.Limits(); commands.detail.maximumCommands = 2
        var commandBytes = Adapter.Limits(); commandBytes.detail.maximumCommandBytes = 240
        var sections = Adapter.Limits(); sections.detail.maximumSections = 1
        var names = Adapter.Limits(); names.detail.maximumNameBytes = 79
        var output = Adapter.Limits(); output.detail.maximumOutputBytes = 4_096
        for limits in [commands, commandBytes, sections, names, output] {
            let limited = try await capture(h, limits: limits)
            requireRefusal(try delivery(limited), .detailLimit)
        }
        var index = Adapter.Limits(); index.detail.indexLimits.maximumEntries = 1
        let grounded = try await capture(h, limits: index)
        requireRefusal(try delivery(grounded), .indexLimit)
    }
    func testWholeWrapperAndEscapedDetailHavePositiveAndAtomicCaps() async throws {
        var bytes = fixture(); for i in 616..<632 { bytes[i] = 0 }
        name(&bytes, 616, "\"\\field")
        let h = try harness(bytes: bytes); defer { h.session.close() }
        var limits = Adapter.Limits(); limits.maximumSerializedBytes = 32_768
        let prepared = try await capture(h, limits: limits), value = try delivery(prepared)
        XCTAssertEqual(value.detail?.sections[0].sectionName, "\"\\field")
        try Adapter.publish(prepared) { XCTAssertLessThanOrEqual($0.count, 32_768) }
        limits.maximumSerializedBytes = 10_000
        do { _ = try await capture(h, limits: limits); XCTFail("wrapper budget omitted") }
        catch { XCTAssertEqual(error as? Adapter.Failure, .outputLimit) }
    }
    func testGroundingAndDetailRefusalsRemainTypedAndAdmissionBound() async throws {
        var unsupported = fixture(); put32(&unsupported, 0, 0x706d6f63)
        var malformed = fixture(); put32(&malformed, 20, 32)
        var detail = fixture(); detail[632] = 65
        let cases: [(Data, Adapter.Refusal)] = [(unsupported, .indexUnsupported(offset: 0)),
            (malformed, .indexMalformed(offset: 32)), (detail, .detailMalformed(parentOffset: 616))]
        for (bytes, reason) in cases {
            let h = try harness(bytes: bytes); defer { h.session.close() }
            let prepared = try await capture(h), value = try delivery(prepared)
            requireRefusal(value, reason)
            XCTAssertEqual(value.parent, try selector(h).parent)
            h.session.close(); suppress(prepared)
        }
    }
    func testCloseReopenSuppressesPreparedSuccessAndTypedRefusal() async throws {
        for kind in Outcome.allCases {
            let input = try outcome(kind), h = input.harness
            let prepared = try await capture(h, selecting: input.selection, limits: input.limits)
            requireOutcome(try delivery(prepared), input: input)
            h.session.close()
            let replacement = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
                source: h.store, io: WorkspaceDocumentIO(), reservations: h.reservations)
            defer { replacement.close() }
            suppress(prepared)
        }
    }
    func testRevisionAndSameSlotNewOwnerSuppressPreparedOutcomes() async throws {
        for kind in Outcome.allCases { for reuse in [false, true] {
            let input = try outcome(kind), h = input.harness; defer { h.session.close() }
            let prepared = try await capture(h, selecting: input.selection, limits: input.limits)
            requireOutcome(try delivery(prepared), input: input)
            if reuse {
                let next = try harness(); defer { next.session.close() }
                h.store.snapshot = next.store.snapshot
            } else {
                var snapshot = h.store.snapshot
                snapshot.analysisBySlot[.primary]?.imageBytes[31] = 1
                h.store.snapshot = snapshot
            }
            suppress(prepared)
        } }
    }
    func testCancellationAtSinkSuppressesSuccessAndTypedRefusal() async throws {
        for kind in Outcome.allCases {
            let input = try outcome(kind), h = input.harness; defer { h.session.close() }
            var cancelled = false
            let prepared = try await Adapter.capture(slot: .primary, store: h.store, session: h.session,
                selecting: input.selection, limits: input.limits, isCancelled: { cancelled })
            requireOutcome(try delivery(prepared), input: input)
            cancelled = true; suppress(prepared)
        }
    }
    func testOriginalDeadlineAtSinkSuppressesSuccessAndTypedRefusal() async throws {
        for kind in Outcome.allCases {
            let input = try outcome(kind), h = input.harness; defer { h.session.close() }
            let start = ContinuousClock().now; var instant = start
            let prepared = try await Adapter.capture(slot: .primary, store: h.store, session: h.session,
                selecting: input.selection, limits: input.limits, now: { instant })
            requireOutcome(try delivery(prepared), input: input)
            instant = start.advanced(by: .seconds(10)); suppress(prepared)
        }
    }
    func testPreCaptureCancellationAndElapsedWorkReturnNoAuthority() async throws {
        let h = try harness(); defer { h.session.close() }
        let selected = try selector(h)
        do {
            _ = try await Adapter.capture(slot: .primary, store: h.store, session: h.session,
                selecting: selected, isCancelled: { true })
            XCTFail("cancelled capture returned authority")
        } catch { XCTAssertEqual(error as? Adapter.Failure, .cancelled) }
        for kind in [Outcome.success, .selector] {
            let input = try outcome(kind); defer { input.harness.session.close() }
            let start = ContinuousClock().now; var observations = 0
            do {
                _ = try await Adapter.capture(slot: .primary, store: input.harness.store, session: input.harness.session,
                    selecting: input.selection, limits: input.limits, now: {
                        observations += 1
                        return observations < 4 ? start : start.advanced(by: .seconds(10))
                    })
                XCTFail("elapsed capture returned authority")
            } catch { XCTAssertEqual(error as? Adapter.Failure, .timedOut) }
        }
    }
    func testDecodedDetailIndexAndDeliveryRemainInertUntilFreshCapture() async throws {
        let h = try harness(); defer { h.session.close() }
        let prepared = try await capture(h), value = try delivery(prepared)
        let detail = try XCTUnwrap(value.detail)
        let decodedDetail = try JSONDecoder().decode(MachOFilesetChildInspection.self,
            from: JSONEncoder().encode(detail))
        let index = MachOFilesetIndex(parent: detail.identity.parent, entries: [])
        let decodedIndex = try JSONDecoder().decode(MachOFilesetIndex.self, from: JSONEncoder().encode(index))
        let decodedDelivery = try JSONDecoder().decode(Adapter.Delivery.self, from: JSONEncoder().encode(value))
        XCTAssertEqual(decodedDetail.identity, detail.identity); XCTAssertTrue(decodedIndex.entries.isEmpty)
        XCTAssertEqual(decodedDelivery.selection, detail.identity)
        h.session.close(); suppress(prepared)
        let replacement = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
            source: h.store, io: WorkspaceDocumentIO(), reservations: h.reservations)
        defer { replacement.close() }
        let fresh = try await Adapter.capture(slot: .primary, store: h.store, session: replacement,
            selecting: decodedDetail.identity)
        XCTAssertEqual(try delivery(fresh).status, .inspected)
    }
    func testReuseAndDeferredDeliveryRecheckOriginalAuthorityEveryTime() async throws {
        for kind in Outcome.allCases {
            let input = try outcome(kind), h = input.harness; defer { h.session.close() }
            let prepared = try await capture(h, selecting: input.selection, limits: input.limits)
            requireOutcome(try delivery(prepared), input: input)
            var writes = 0
            var deferred: (() throws -> Void)?
            try Adapter.publish(prepared) { _ in
                deferred = { try Adapter.publish(prepared) { _ in writes += 1 } }
            }
            try XCTUnwrap(deferred)(); XCTAssertEqual(writes, 1)
            var snapshot = h.store.snapshot
            snapshot.analysisBySlot[.primary]?.imageBytes[31] = 1
            h.store.snapshot = snapshot
            XCTAssertThrowsError(try XCTUnwrap(deferred)()); XCTAssertEqual(writes, 1)
            suppress(prepared)
        }
    }
}

@MainActor
private final class FilesetChildDetailReservations: WorkspaceDocumentLocationReserving {
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

