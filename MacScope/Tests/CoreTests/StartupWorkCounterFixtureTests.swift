import Foundation
import XCTest
@testable import MacScope

/// Item 1330 (TC06, TC07): pure and empty arms for the propagation and string-recovery
/// counters. Loader, metadata and nonempty-model arms stay OPEN (OP6).
final class StartupWorkCounterFixtureTests: XCTestCase {
    private typealias Field = StartupWorkCounters.Field

    private struct Stop: Error {}

    private func active() -> StartupWorkCounters {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        return work
    }

    // Empty propagation: one call is counted; the index and round sites are never reached.
    func testEmptyPropagationCountsCallsOnly() {
        let work = active()
        XCTAssertTrue(NoReturnAnalysis.propagate(functions: [], instructions: [], known: [], work: work).isEmpty)
        XCTAssertTrue(NoReturnAnalysis.propagate(functions: [], instructions: [], known: [], work: work).isEmpty)
        work.close(.discovery)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.propagationCalls], 2)
        XCTAssertNil(values[.propagationIndexBuilds], "an unreached site stays absent")
        XCTAssertNil(values[.propagationIndexRows])
        XCTAssertNil(values[.propagationInnerRounds])
        XCTAssertNil(values[.functionsConsidered])
    }

    func testAbsentObserverLeavesEmptyPropagationUnchanged() {
        XCTAssertTrue(NoReturnAnalysis.propagate(functions: [], instructions: [], known: []).isEmpty)
    }

    // Empty recoverer: early return with no references still counts the call, no loop fields.
    func testEmptyStringRecoveryCountsCallOnly() throws {
        let work = active()
        let result = try ReferencedStringRecovery.recover(
            retained: [], coverage: nil, references: [], sections: [], bytes: Data(),
            sliceOffset: 0, sliceSize: nil, overlay: .empty, work: work, checkpoint: {})
        XCTAssertTrue(result.isEmpty)
        work.close(.string)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.stringRecoveryCalls], 1)
        XCTAssertNil(values[.stringSectionEntriesVisited])
        XCTAssertNil(values[.stringReferencesVisited])
        XCTAssertNil(values[.stringAdditions])
    }

    func testStringRecoveryCheckpointFailureLeavesCallAbsent() {
        let work = active()
        XCTAssertThrowsError(try ReferencedStringRecovery.recover(
            retained: [], coverage: nil, references: [], sections: [], bytes: Data(),
            sliceOffset: 0, sliceSize: nil, overlay: .empty, work: work, checkpoint: { throw Stop() }))
        work.close(.string)
        work.finishAnalysis(.success)
        XCTAssertNil(work.snapshot().values[.stringRecoveryCalls], "a call that did not return is not certified")
    }

    func testCoverageCompleteReturnsRetainedAndCountsCall() throws {
        let work = active()
        _ = try ReferencedStringRecovery.recover(
            retained: [], coverage: .complete, references: [], sections: [], bytes: Data(),
            sliceOffset: 0, sliceSize: nil, overlay: .empty, work: work, checkpoint: {})
        work.close(.string)
        work.finishAnalysis(.success)
        XCTAssertEqual(work.snapshot().values[.stringRecoveryCalls], 1)
    }
}
