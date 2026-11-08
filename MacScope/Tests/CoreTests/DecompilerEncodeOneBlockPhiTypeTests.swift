import Foundation
import Darwin
import XCTest
@testable import MacScope

/// DIAG-1260: libjpeg `_encode_one_block` in SSA mode must render in seconds.
/// The C2 census stalled on this function because each phi edge copy re-solved
/// the whole-function unsigned phi proof.
final class DecompilerEncodeOneBlockPhiTypeTests: XCTestCase {
    @MainActor
    func testLibjpegEncodeOneBlockRendersQuicklyInSSA() throws {
        let path = "/opt/homebrew/lib/libjpeg.8.dylib"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("libjpeg witness input is absent")
        }
        guard MacIRConfiguration.ssaEnabled else {
            throw XCTSkip("Run with TEST_RUNNER_MACSCOPE_SSA_LIFTER=1")
        }
        // Explicit watchdog: a runaway render ends the test host after 120 s.
        let watchdog = DispatchSource.makeTimerSource(queue: .global())
        watchdog.schedule(deadline: .now() + 120)
        watchdog.setEventHandler {
            print("DIAG1260_WATCHDOG expired after 120 s")
            fflush(stdout)
            _exit(3)
        }
        watchdog.resume()
        defer { watchdog.cancel() }

        let initial = try AnalysisEngine().analyze(url: URL(fileURLWithPath: path))
        let headers = try CalleeWitnessHeaders.load(into: initial)
        let ownReturnAuthority = try C2OwnReturnAuthority.load(into: headers.snapshot)
        let snapshot = ownReturnAuthority.snapshot
        let slot = snapshot.primarySlot
        let analysis = try XCTUnwrap(snapshot.analysis(in: slot))
        let identity = try XCTUnwrap(analysis.functions.first { $0.name == "_encode_one_block" })
        let printer = PseudocodePrinter(options: DecompilerOptions(userDefaults: .standard))
        let input = snapshot.pseudocodeRenderInput(selectedAddress: identity.startAddress, in: slot)
        let began = Date()
        let function = DecompilerC2DataflowCensusTests.buildFunction(printer: printer, input: input)
        let built = Date()
        XCTAssertTrue(function.ssaEnabled)
        let document = printer.print(function: function, types: input.types,
            nameOverrides: input.nameOverrides, registerNameOverrides: input.registerNameOverrides,
            stackLocalOverrides: input.stackLocalOverrides, resolvedIndirectCalls: input.resolvedIndirectCalls)
        let done = Date()
        print("DIAG1260 phis=\(function.phis.count) instructions=\(function.instructions.count) build=\(built.timeIntervalSince(began)) render=\(done.timeIntervalSince(built))")
        XCTAssertFalse(document.lines.isEmpty)
        XCTAssertLessThan(done.timeIntervalSince(built), 10)
    }
}
