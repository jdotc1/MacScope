import Foundation
import XCTest
@testable import MacScope

final class BinarySearchPreparationTests: XCTestCase {
    private final class Probe: @unchecked Sendable {
        private let lock = NSLock()
        private var recorded: [BinarySearchService.PreparationEvent] = []
        private var checks = 0
        private var instant = Date(timeIntervalSince1970: 0)

        func record(_ event: BinarySearchService.PreparationEvent) {
            lock.lock(); defer { lock.unlock() }
            recorded.append(event)
        }
        var events: [BinarySearchService.PreparationEvent] {
            lock.lock(); defer { lock.unlock() }
            return recorded
        }
        func cancellationCheck() -> Bool {
            lock.lock(); defer { lock.unlock() }
            checks += 1
            return false
        }
        var cancellationCalls: Int {
            lock.lock(); defer { lock.unlock() }
            return checks
        }
        func now() -> Date {
            lock.lock(); defer { lock.unlock() }
            return instant
        }
        func expire() {
            lock.lock(); defer { lock.unlock() }
            instant = Date(timeIntervalSince1970: 3)
        }
    }

    private func fixture(overridesPerImage: Int = 1) -> WorkspaceSnapshot {
        let slots = [ImageSlot(rawValue: 1), .primary]
        let binaries = slots.map {
            BinaryImage(id: UUID(), name: "image-\($0.rawValue)",
                        path: $0 == .primary ? "/fixture" : "/System/fixture",
                        kind: "Mach-O", architecture: "arm64", slot: $0)
        }
        var analyses: [ImageSlot: ImageAnalysis] = [:]
        var overrides: [ImageAddress: AddressOverride] = [:]
        for slot in slots {
            var analysis = ImageAnalysis()
            analysis.instructions = [InstructionRow(address: 0x1000, bytes: "11 22 33 44",
                mnemonic: "needle", operands: "", hasBreakpoint: false, comment: nil)]
            analyses[slot] = analysis
            for index in 0..<overridesPerImage {
                var value = AddressOverride()
                value.customComment = "annotation"
                overrides[ImageAddress(slot: slot, address: 0x2000 + UInt64(index) * 4)] = value
            }
        }
        return WorkspaceSnapshot(binaries: binaries, analysisBySlot: analyses, addressOverrides: overrides)
    }

    private func assertEmptyExhausted(_ outcome: BinarySearchService.BoundedOutcome,
                                      file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(outcome.results.isEmpty, file: file, line: line)
        XCTAssertEqual(outcome.lowerBound, 0, file: file, line: line)
        XCTAssertTrue(outcome.isTruncated, file: file, line: line)
        XCTAssertFalse(outcome.isCancelled, file: file, line: line)
    }

    // Requires the new internal seam. With the seam alone and no checkpoints,
    // this fails by returning two matches without truncation.
    func testPreparationExhaustionAtFirstCheckpointPrecedesEveryScan() {
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(overridesPerImage: 512), isCancelled: { false },
            preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in probe.record(event); return true },
            clock: { probe.now() })
        assertEmptyExhausted(outcome)
        XCTAssertEqual(probe.events, [.image(ImageSlot(rawValue: 1))])
    }

    // The override loop, not just image boundaries, must observe the checkpoint.
    func testOverrideFilteringCanStopBeforeAnyProjectionCompletes() {
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(overridesPerImage: 512), isCancelled: { false },
            preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in
                probe.record(event)
                if case .overrideEntry = event { return true }
                return false
            }, clock: { probe.now() })
        assertEmptyExhausted(outcome)
        XCTAssertEqual(probe.events, [.image(ImageSlot(rawValue: 1)), .overrideEntry(ImageSlot(rawValue: 1))])
    }

    // Prepared earlier images must not leak matches when later preparation stops.
    func testPreparationStopBetweenImagesDiscardsEarlierProjections() {
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(), isCancelled: { false }, preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in
                probe.record(event)
                return event == .image(.primary)
            }, clock: { probe.now() })
        assertEmptyExhausted(outcome)
        XCTAssertEqual(probe.events.last, .image(.primary))
        XCTAssertEqual(probe.events.filter { if case .overrideEntry = $0 { return true }; return false }.count, 2)
    }

    // Deadline expiry uses the real stopped predicate, not the cancellation flag or a sleep.
    func testDeadlineCanExpireInsideOverridePreparation() {
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .regex,
            in: fixture(overridesPerImage: 512), isCancelled: { false },
            preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in
                probe.record(event)
                if case .overrideEntry = event { probe.expire() }
                return false
            }, clock: { probe.now() })
        assertEmptyExhausted(outcome)
        XCTAssertEqual(probe.events.count, 2)
    }

    // Cancellation stops before projecting the first included image; excluded images have no event.
    func testAlreadyCancelledPreparationDoesNotProjectExcludedImages() {
        var scope = BinarySearchScope.everything
        scope.excludesSystemImages = true
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(overridesPerImage: 512), scope: scope, isCancelled: { true },
            preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in probe.record(event); return false },
            clock: { probe.now() })
        XCTAssertTrue(outcome.results.isEmpty)
        XCTAssertEqual(outcome.lowerBound, 0)
        XCTAssertTrue(outcome.isCancelled)
        XCTAssertFalse(outcome.isTruncated)
        XCTAssertEqual(probe.events, [.image(.primary)])
    }

    // No image reaches the old per-image stopped check, so no new exhaustion is observable.
    func testAllExcludedKeepsFinalOnlyCancellationAndNoTruncation() {
        var scope = BinarySearchScope.everything
        scope.images = .focused
        scope.focusedSlot = ImageSlot(rawValue: 9)
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(overridesPerImage: 512), scope: scope,
            isCancelled: { probe.cancellationCheck() },
            preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in probe.record(event); return true },
            clock: { probe.now() })
        XCTAssertTrue(outcome.results.isEmpty)
        XCTAssertEqual(outcome.lowerBound, 0)
        XCTAssertFalse(outcome.isTruncated)
        XCTAssertFalse(outcome.isCancelled)
        XCTAssertTrue(probe.events.isEmpty)
        XCTAssertEqual(probe.cancellationCalls, 1)
    }

    // Default preparation cadence: two images, two candidate visits, two appends and final publication.
    func testSmallTextSearchKeepsCancellationCallFormulaAndSlotOrder() {
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(), isCancelled: { probe.cancellationCheck() },
            preparationCheckpoint: { event in probe.record(event); return false },
            clock: { probe.now() })
        XCTAssertEqual(outcome.results.map(\.imageSlot), [.primary, ImageSlot(rawValue: 1)])
        XCTAssertEqual(outcome.results.map(\.address), [0x1000, 0x1000])
        XCTAssertEqual(outcome.lowerBound, 2)
        XCTAssertFalse(outcome.isTruncated)
        XCTAssertFalse(outcome.isCancelled)
        let includedImages = 2, candidateVisits = 2, successfulAppends = 2
        XCTAssertEqual(probe.cancellationCalls, includedImages + candidateVisits + successfulAppends + 1)
        XCTAssertEqual(probe.cancellationCalls, 7)
        XCTAssertTrue(probe.events.isEmpty)
    }

    // Defaults still check large preparation; the seam does not lower the production interval.
    func testDefaultCadenceReachesTheOverrideLoop() {
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
            in: fixture(overridesPerImage: 512), isCancelled: { false },
            preparationCheckpoint: { event in probe.record(event); return true },
            clock: { probe.now() })
        assertEmptyExhausted(outcome)
        XCTAssertEqual(probe.events, [.overrideEntry(ImageSlot(rawValue: 1))])
    }

    // Scoping, authored text and the binary-less compatibility projection retain their results.
    func testSmallScopesAuthoredTextAndBinarylessFallback() {
        let service = BinarySearchService()
        var snapshot = fixture()
        var authored = AddressOverride()
        authored.customName = "authoredName"
        authored.customComment = "authoredComment"
        authored.tag = "authoredTag"
        snapshot.addressOverrides[ImageAddress(slot: .primary, address: 0x1000)] = authored
        let probe = Probe()
        for query in ["authoredName", "authoredComment", "authoredTag"] {
            let outcome = service.searchBounded(query: query, mode: .text, in: snapshot, clock: { probe.now() })
            XCTAssertEqual(outcome.results.map(\.imageSlot), [.primary])
            XCTAssertEqual(outcome.results.map(\.address), [0x1000])
            XCTAssertFalse(outcome.isTruncated)
        }
        var scope = BinarySearchScope.everything
        scope.images = .focused
        scope.focusedSlot = .primary
        let focused = service.searchBounded(query: "needle", mode: .text, in: snapshot,
                                            scope: scope, clock: { probe.now() })
        XCTAssertEqual(focused.results.map(\.imageSlot), [.primary])
        scope.kinds = [.string]
        let excludedKind = service.searchBounded(query: "needle", mode: .text, in: snapshot,
                                                 scope: scope, clock: { probe.now() })
        XCTAssertTrue(excludedKind.results.isEmpty)
        XCTAssertFalse(excludedKind.isTruncated)
        let legacy = WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: snapshot.analysisBySlot[.primary]!],
                                       addressOverrides: snapshot.addressOverrides)
        let legacyHits = service.searchBounded(query: "needle", mode: .text, in: legacy, clock: { probe.now() })
        XCTAssertEqual(legacyHits.results, focused.results)
        XCTAssertEqual(service.searchWithCount(query: "needle", mode: .text, in: snapshot).total, 2)
    }

    // Hex uses the same checkpointed projections and keeps image-qualified effective-byte patches.
    func testHexProjectionPreservesPatchAndCanStopDuringPreparation() {
        var snapshot = fixture()
        var patch = AddressOverride()
        patch.patch = BytePatch(bytes: [0xaa, 0xbb])
        snapshot.addressOverrides[ImageAddress(slot: ImageSlot(rawValue: 1), address: 0x1001)] = patch
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "aa bb", mode: .hex, in: snapshot,
                                                           clock: { probe.now() })
        XCTAssertEqual(outcome.results.map(\.imageSlot), [ImageSlot(rawValue: 1)])
        XCTAssertEqual(outcome.results.map(\.address), [0x1001])
        XCTAssertFalse(outcome.isTruncated)
        let stopped = BinarySearchService().searchBounded(query: "aa bb", mode: .hex, in: snapshot,
            isCancelled: { false }, preparationCheckpointInterval: 1,
            preparationCheckpoint: { _ in true }, clock: { probe.now() })
        assertEmptyExhausted(stopped)
        var scope = BinarySearchScope.everything
        scope.kinds = [.instruction]
        let skipped = BinarySearchService().searchBounded(query: "aa bb", mode: .hex, in: snapshot,
            scope: scope, preparationCheckpointInterval: 1,
            preparationCheckpoint: { event in probe.record(event); return true }, clock: { probe.now() })
        XCTAssertTrue(skipped.results.isEmpty)
        XCTAssertFalse(skipped.isTruncated)
        XCTAssertTrue(probe.events.isEmpty)
    }

    // Existing match/visit bounds are not spent on preparation.
    func testAccumulationCapRemainsFiveHundredWithLowerBoundFiveHundredOne() {
        var snapshot = fixture()
        snapshot.analysisBySlot[.primary]?.instructions = (0..<2_000).map {
            InstructionRow(address: UInt64(0x1000 + $0 * 4), bytes: "00", mnemonic: "needle",
                           operands: "", hasBreakpoint: false, comment: nil)
        }
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text,
                                                           in: snapshot, clock: { probe.now() })
        XCTAssertEqual(outcome.results.count, 500)
        XCTAssertEqual(outcome.lowerBound, 501)
        XCTAssertTrue(outcome.isTruncated)
        XCTAssertFalse(outcome.isCancelled)
    }

    // Raw-section hex behavior is unchanged as well as the instruction-stream fallback.
    func testSectionHexStillUsesImageQualifiedPatch() {
        var snapshot = fixture()
        let slot = ImageSlot(rawValue: 1)
        snapshot.analysisBySlot[slot]?.imageBytes = Data([0x11, 0x22, 0x33, 0x44])
        snapshot.analysisBySlot[slot]?.sections = [
            SectionSummary(id: UUID(), name: "__text", address: 0x1000, size: 4,
                           fileOffset: 0, isExecutable: true, isZeroFill: false)
        ]
        var patch = AddressOverride()
        patch.patch = BytePatch(bytes: [0xaa, 0xbb])
        snapshot.addressOverrides[ImageAddress(slot: slot, address: 0x1001)] = patch
        let probe = Probe()
        let outcome = BinarySearchService().searchBounded(query: "aa bb", mode: .hex,
                                                           in: snapshot, clock: { probe.now() })
        XCTAssertEqual(outcome.results.map(\.imageSlot), [slot])
        XCTAssertEqual(outcome.results.map(\.address), [0x1001])
        XCTAssertFalse(outcome.isTruncated)
    }

}
