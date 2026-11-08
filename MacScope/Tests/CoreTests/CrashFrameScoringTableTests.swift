import Foundation
import XCTest
@testable import MacScope

/// DC2 acceptance harness: the crash-frame scoring-table builder over in-test reports and typed
/// symbolicator answers. Nothing here reads the host's dyld cache or any crash report on disk.
final class CrashFrameScoringTableTests: XCTestCase {
    private func makeReport(frames: [[String: Any]]) throws -> CrashReport {
        let body: [String: Any] = [
            "procName": "probe",
            "osVersion": ["build": "99A1", "train": "macOS 99", "releaseType": "User"],
            "usedImages": [
                ["name": "libsystem_kernel.dylib", "uuid": "11111111-2222-3333-4444-555555555555",
                 "base": 0x1_8000_0000, "size": 0x10000, "source": "S"],
                ["name": "probe", "uuid": "66666666-2222-3333-4444-555555555555",
                 "base": 0x1_0000_0000, "size": 0x4000, "source": "P"],
            ],
            "threads": [["triggered": true, "frames": frames]],
        ]
        return try CrashReport.parse(try JSONSerialization.data(withJSONObject: body))
    }

    private func named(_ names: [String], offset: UInt64) -> FrameSymbolOutcome {
        .named(NamedFrame(
            names: names.map { SymbolName(bytes: Array($0.utf8), display: $0, source: .exportTrieExact) },
            functionStart: 0x1000, functionEnd: 0x2000, offsetWithinSymbol: offset,
            imagePath: Array("/usr/lib/system/libsystem_kernel.dylib".utf8), imageUUID: [UInt8](repeating: 0x11, count: 16),
            address: 0x1000 + offset, imageOffset: 0x1000 + offset, buildUnchecked: false))
    }

    private func symbolication(_ outcomes: [FrameSymbolOutcome]) -> CrashSymbolication {
        CrashSymbolication(
            cacheUUID: [UInt8](repeating: 0xab, count: 16),
            frames: outcomes.enumerated().map { index, outcome in
                FrameSymbolication(threadIndex: 0, frameID: index, reportImageIndex: 0,
                                   coverAdjustment: index == 0 ? 0 : 1,
                                   cacheUUID: [UInt8](repeating: 0xab, count: 16), outcome: outcome)
            },
            buildChecked: true, refusal: nil, wasCancelled: false)
    }

    private func frame(_ image: Int, _ offset: UInt64, symbol: String?, location: UInt64?) -> [String: Any] {
        var value: [String: Any] = ["imageIndex": image, "imageOffset": offset]
        if let symbol { value["symbol"] = symbol }
        if let location { value["symbolLocation"] = location }
        return value
    }

    func testVerdictsUnderscoreRuleAndCountsSumToTheTotal() throws {
        let report = try makeReport(frames: [
            frame(0, 0x1010, symbol: "__pthread_kill", location: 8),     // MacScope "___pthread_kill": one strip equals the oracle
            frame(0, 0x1020, symbol: "pthread_kill", location: 4),       // match after one strip
            frame(0, 0x1030, symbol: "abort", location: 4),              // name differs: mismatch
            frame(0, 0x1040, symbol: "raise", location: 6),              // offset differs: mismatch
            frame(1, 0x20, symbol: "main", location: 0),                 // typed refusal
            frame(1, 0x40, symbol: nil, location: nil),                  // oracle has no symbol
            frame(0, 0x1050, symbol: "_exact", location: 2),             // equal without stripping
        ])
        let outcomes: [FrameSymbolOutcome] = [
            named(["___pthread_kill"], offset: 8),
            named(["_pthread_kill"], offset: 4),
            named(["_raise"], offset: 4),
            named(["_raise"], offset: 8),
            .imageNotInCache(ImageNotInCache(reportImageName: "probe", reportUUID: nil, catalogCount: 3, skippedSource: .process)),
            .noSymbolCovering(.outsideAnyImage),
            named(["_exact", "_other"], offset: 2),
        ]
        let table = try XCTUnwrap(CrashFrameScoringTable.build(
            report: report, threadIndex: 0, symbolication: symbolication(outcomes)))
        XCTAssertEqual(table.rows.map(\.verdict), [.match, .match, .mismatch, .mismatch, .typedUnnamed, .oracleUnnamed, .match])
        XCTAssertEqual(table.verdictCounts, ["match": 3, "mismatch": 2, "typedUnnamed": 1, "oracleUnnamed": 1])
        XCTAssertEqual(table.frameTotal, 7)
        // A second strip is never applied: "__x" does not match oracle "x".
        let double = try makeReport(frames: [frame(0, 0x1010, symbol: "x", location: 0)])
        let two = try XCTUnwrap(CrashFrameScoringTable.build(
            report: double, threadIndex: 0, symbolication: symbolication([named(["__x"], offset: 0)])))
        XCTAssertEqual(two.rows[0].verdict, .mismatch)
        XCTAssertTrue(table.countsSumToTotal)
        XCTAssertEqual(table.rows[3].mismatchDetail, "offset: oracle symbolLocation 6 vs MacScope 8")
        XCTAssertEqual(table.rows[4].outcome, "imageNotInCache")
        XCTAssertNotNil(table.rows[4].reason)
        XCTAssertEqual(table.rows[0].imageName, "libsystem_kernel.dylib")
        XCTAssertEqual(table.rows[4].imageName, "probe")
        XCTAssertEqual(table.reportOSBuild, "99A1")
        XCTAssertTrue(table.normalization.contains("exactly one normalization"))
        XCTAssertNoThrow(try table.encoded())
    }

    func testMissingRecordAndMissingThreadAreHandled() throws {
        let report = try makeReport(frames: [frame(0, 0x1010, symbol: "abort", location: 1)])
        let empty = CrashSymbolication(cacheUUID: [], frames: [], buildChecked: true, refusal: nil, wasCancelled: false)
        let table = try XCTUnwrap(CrashFrameScoringTable.build(report: report, threadIndex: 0, symbolication: empty))
        XCTAssertEqual(table.rows[0].verdict, .typedUnnamed)
        XCTAssertEqual(table.rows[0].outcome, "noRecord")
        XCTAssertTrue(table.countsSumToTotal)
        XCTAssertNil(CrashFrameScoringTable.build(report: report, threadIndex: 5, symbolication: empty))
    }
}
