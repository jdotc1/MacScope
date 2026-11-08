import Foundation
import XCTest
@testable import MacScope

/// DC2-4: the row-model helper and the model's cancel path. Synthetic outcomes only; no cache,
/// no crash report on disk, no window.
@MainActor
final class CrashFrameNamingTests: XCTestCase {
    private func named(_ names: [String], offset: UInt64 = 0x10) -> FrameSymbolOutcome {
        .named(NamedFrame(
            names: names.map { SymbolName(bytes: Array($0.utf8), display: $0, source: .exportTrieExact) },
            functionStart: 0x1000, functionEnd: 0x1100, offsetWithinSymbol: offset,
            imagePath: Array("/usr/lib/libx.dylib".utf8), imageUUID: [UInt8](repeating: 1, count: 16),
            address: 0x1010, imageOffset: 0x10, buildUnchecked: false))
    }

    func testNamedShowsCacheNamesAndOffsetLabelledAsHostCache() {
        let display = CrashFrameNameDisplay.make(outcome: named(["_a", "_b"], offset: 0x2a), reportedSymbol: nil)
        XCTAssertEqual(display, .named(names: ["_a", "_b"], offset: 0x2a, reportedSymbol: nil))
        XCTAssertEqual(display?.text, "Host cache: _a / _b + 0x2a")
    }

    func testNamedWithSameReportedSymbolDoesNotRepeatIt() {
        let display = CrashFrameNameDisplay.make(outcome: named(["_a"]), reportedSymbol: "_a")
        XCTAssertEqual(display, .named(names: ["_a"], offset: 0x10, reportedSymbol: nil))
    }

    func testNamedWithDifferingReportedSymbolShowsBothAndReplacesNeither() {
        let display = CrashFrameNameDisplay.make(outcome: named(["_a"]), reportedSymbol: "other")
        XCTAssertEqual(display, .named(names: ["_a"], offset: 0x10, reportedSymbol: "other"))
        XCTAssertEqual(display?.text, "Host cache: _a + 0x10 (report says other)")
    }

    func testEveryRefusalFamilyShowsNoNameAndOneTypedReasonLine() {
        let refusals: [(FrameSymbolOutcome, String)] = [
            (.cacheMismatch(.osBuildDiffers(report: "1", host: "2")), "not named: report is from a different OS build"),
            (.cacheMismatch(.hostBuildUnavailable), "not named: host OS build unavailable"),
            (.cacheMismatch(.slideInconsistent), "not named: inconsistent image slide"),
            (.imageNotInCache(ImageNotInCache(reportImageName: "x", reportUUID: nil, catalogCount: 3, skippedSource: nil)),
             "not named: image not in the host cache"),
            (.noSymbolCovering(.stubSection("__stubs")), "not named: stub section"),
            (.noSymbolCovering(.startUnnamed(0x10)), "not named: no exported name at the function start"),
            (.ambiguous(.duplicateImageUUID(paths: [], moreCandidates: false)), "not named: image is ambiguous in the host cache"),
            (.malformed(.nameNotUTF8), "not named: symbol name is not valid text"),
            (.cancelled, "not named: cancelled"),
        ]
        for (outcome, expected) in refusals {
            let display = CrashFrameNameDisplay.make(outcome: outcome, reportedSymbol: "reported")
            XCTAssertEqual(display, .notNamed(reason: expected))
            XCTAssertEqual(display?.text, expected)
            XCTAssertFalse(display!.text.contains("reported"), "a refusal never echoes or guesses a name")
            XCTAssertFalse(display!.text.contains("\n"))
        }
    }

    func testOwnImageAddsNothingAndKeepsLoadTheBinaryMessage() throws {
        let outcome = FrameSymbolOutcome.imageNotInCache(ImageNotInCache(
            reportImageName: "App", reportUUID: nil, catalogCount: 1, skippedSource: .process))
        XCTAssertNil(CrashFrameNameDisplay.make(outcome: outcome, reportedSymbol: nil))

        let uuid = "11111111-2222-3333-4444-555555555555"
        let report = CrashReport(
            processName: "p", exceptionSummary: "e",
            threads: [CrashReportThread(id: 0, name: nil, triggered: true,
                frames: [CrashReportFrame(id: 0, imageIndex: 0, imageOffset: 0x10, reportedSymbol: nil)])],
            images: [CrashReportImage(name: "App", uuid: uuid, base: 0x1000, size: 0x100, source: .process)])
        let other = CrashReportImageContext(uuid: "AAAAAAAA-2222-3333-4444-555555555555", preferredBase: 0, mappedRanges: [], symbols: [])
        let match = report.match(report.threads[0].frames[0], contexts: [other])
        XCTAssertEqual(match.resolved.diagnostic, "Load the binary with this UUID, then reopen the report")
    }

    private func sampleReport() -> CrashReport {
        CrashReport(
            processName: "p", exceptionSummary: "e",
            threads: [CrashReportThread(id: 3, name: nil, triggered: true,
                frames: [CrashReportFrame(id: 7, imageIndex: nil, imageOffset: nil, reportedSymbol: nil)])],
            images: [])
    }

    func testModelPublishesOutcomesByThreadAndFrame() async throws {
        let model = CrashFrameNamingModel { _, _ in
            .success(CrashSymbolication(
                cacheUUID: [], frames: [FrameSymbolication(
                    threadIndex: 3, frameID: 7, reportImageIndex: nil, coverAdjustment: 0, cacheUUID: [], outcome: .cancelled)],
                buildChecked: true, refusal: nil, wasCancelled: false))
        }
        model.start(report: sampleReport())
        for _ in 0..<200 where model.isRunning { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(model.outcomes[.init(threadID: 3, frameID: 7)], .cancelled)
        XCTAssertNil(model.note)
    }

    func testHostCacheUnavailableSetsOneNoteAndNoRows() async throws {
        let model = CrashFrameNamingModel { _, _ in .failure(CacheUnavailableError(.notPresent, "none")) }
        model.start(report: sampleReport())
        for _ in 0..<200 where model.isRunning { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(model.outcomes.isEmpty)
        XCTAssertEqual(model.note, "System frames not named: host cache unavailable (notPresent)")
    }

    /// The window-close path calls `cancel()`; the work must see cancellation and publish nothing.
    func testCancelStopsWorkAndPublishesNothing() async throws {
        let started = DispatchSemaphore(value: 0)
        let observedCancel = XCTestExpectation(description: "work saw cancellation")
        let model = CrashFrameNamingModel { _, isCancelled in
            started.signal()
            while !isCancelled() { usleep(1_000) }
            observedCancel.fulfill()
            return .success(CrashSymbolication(
                cacheUUID: [], frames: [FrameSymbolication(
                    threadIndex: 3, frameID: 7, reportImageIndex: nil, coverAdjustment: 0, cacheUUID: [], outcome: .cancelled)],
                buildChecked: true, refusal: nil, wasCancelled: true))
        }
        model.start(report: sampleReport())
        XCTAssertTrue(model.isRunning)
        XCTAssertEqual(started.wait(timeout: .now() + 5), .success)
        model.cancel()
        XCTAssertFalse(model.isRunning)
        await fulfillment(of: [observedCancel], timeout: 5)
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertTrue(model.outcomes.isEmpty)
        XCTAssertNil(model.note)
    }
}
