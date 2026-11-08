import Foundation
import XCTest
@testable import MacScope

// T7 complete semantic-document guard, F3. Authored, unrun. No scope spans await.
// No timing/core assertion, no production identity or fingerprint change.
final class ReadyParallelDeterminismTests: XCTestCase {
    func testGuardThresholdInputsPreserveOrderedFunctionsAndListing() throws {
        for count in [4095, 4096, 4097, 8192] {
            let rows = ReadyFixture.instructions(count: count)
            let engine = AnalysisEngine(loader: ReadyFixture.Loader(binary:
                ReadyFixture.binary(instructions: rows)), decoder: ReadyFixture.Decoder(rows: rows))
            let sequential = try AnalysisParallelism.withBudget(AnalysisResourceBudget(maximumParallelism: 1)) {
                try engine.analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
            }
            let current = try engine.analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
            XCTAssertEqual(sequential.instructions.count, count)
            XCTAssertFalse(sequential.functions.isEmpty)
            XCTAssertEqual(sequential.instructions, current.instructions)
            XCTAssertEqual(sequential.functions, current.functions)
            XCTAssertEqual(sequential.symbols, current.symbols)
            XCTAssertEqual(sequential.jumpTables, current.jumpTables)
            XCTAssertEqual(sequential.codeDataRanges.count, 0)
            XCTAssertEqual(current.codeDataRanges.count, 0)
            let left = try AnalysisSnapshotCanonicalizer(snapshot: sequential)
            let right = try AnalysisSnapshotCanonicalizer(snapshot: current)
            XCTAssertEqual(try left.canonical(sequential.xrefs), try right.canonical(current.xrefs))
            XCTAssertEqual(try left.canonical(sequential), try right.canonical(current))
        }
    }
}
